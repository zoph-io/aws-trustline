#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Victor Grenu / zoph.io
"""
AWS Trustline - Map and audit third-party trust relationships in your AWS account.

Expands sharing records into grant rows, groups them by external principal,
and resolves 12-digit account IDs against fwd:cloudsec known vendor accounts.
If an Access Analyzer exists it is used by default (effective access); otherwise
IAM trusts and S3 bucket policies are walked. RAM, AMI, SSM, and credentials
always run unless skipped.

Usage:
    python trustline.py
    python trustline.py --profile my-profile --region us-east-1
    python trustline.py --all-regions --format both
    python trustline.py --policy-scanner
    python trustline.py --use-access-analyzer --wait-for-analyzer
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any
from urllib.parse import unquote

import boto3
import requests
import yaml
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from grants import (
    MECHANISM_LABELS,
    SERVICE_SPECIFIC_CREDENTIAL_SERVICES,
    actions_from_ram_permission,
    apply_live_trust_conditions,
    apply_s3_effective_public,
    build_coverage,
    choose_external_analyzer,
    clear_unproven_aa_condition_flags,
    dedupe_access_analyzer_grants,
    empty_grant,
    flatten_condition_keys,
    grant_from_parsed_principal,
    grant_resource_label,
    grants_from_policy_document,
    index_known_accounts,
    is_aws_service_principal,
    merge_builtin_vendors,
    oidc_condition_gaps,
    parse_principal_value,
    parties_from_grants,
    report_scope_label,
    role_name_from_resource,
    should_flag_missing_external_id,
    totals_from_grants,
)

__version__ = "0.4.1"

REFERENCE_DATA_URL = (
    "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
)
DEFAULT_TRUSTED_ACCOUNTS_FILE = "trusted_accounts.yaml"
DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_WAIT_TIMEOUT = 300
CACHE_DIR_ENV = "TRUSTLINE_CACHE_DIR"

# External-access analyzer types (excludes unused-access and internal-access).
EXTERNAL_ANALYZER_TYPES = {"ACCOUNT", "ORGANIZATION"}

# Conservative timeouts + small retry budget for the AA backend so a single
# unreachable region (transient outage, opted-out region, network blackhole)
# cannot stall an --all-regions run for minutes.
AA_CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=20,
    retries={"max_attempts": 2, "mode": "standard"},
)

# Cap on concurrent per-region API calls.
AA_MAX_WORKERS = 8

console = Console()


def _known_accounts_cache_path() -> str:
    base = os.environ.get(CACHE_DIR_ENV) or os.path.join(
        os.path.expanduser("~"), ".cache", "aws-trustline"
    )
    return os.path.join(base, "known_aws_accounts.yaml")


def _write_known_accounts_cache(path: str, body: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        fh.write(body)
    os.replace(tmp, path)


def fetch_reference_data() -> dict[str, dict[str, Any]]:
    """Fetch known AWS accounts from fwd:cloudsec; fall back to a local cache."""
    cache_path = _known_accounts_cache_path()
    try:
        response = requests.get(REFERENCE_DATA_URL, timeout=15)
        response.raise_for_status()
        indexed = index_known_accounts(yaml.safe_load(response.text))
        try:
            _write_known_accounts_cache(cache_path, response.text)
        except OSError as e:
            console.print(f"[yellow]Could not write known-accounts cache: {e}[/yellow]")
        return merge_builtin_vendors(indexed)
    except Exception as e:
        console.print(f"[bold yellow]Could not fetch known AWS accounts: {e}[/bold yellow]")
        try:
            with open(cache_path, "r") as fh:
                cached = fh.read()
            indexed = index_known_accounts(yaml.safe_load(cached))
            console.print(
                f"[green]Using cached known AWS accounts from {cache_path}[/green]"
            )
            return merge_builtin_vendors(indexed)
        except OSError:
            console.print(
                "[yellow]No local cache; resolving names from builtin aliases only.[/yellow]"
            )
            return merge_builtin_vendors({})


def fetch_org_accounts(session: boto3.Session) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Fetch AWS accounts from AWS Organizations API."""
    try:
        org_client = session.client("organizations")
        account_to_internal: dict[str, dict[str, Any]] = {}

        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                account_to_internal[account["Id"]] = {
                    "name": account["Name"],
                    "type": "trusted",
                    "description": "AWS Organization Account",
                    "source": "aws_org",
                }

        console.print(
            f"[green]Found {len(account_to_internal)} accounts in AWS Organization[/green]"
        )
        return account_to_internal, None

    except Exception as e:
        error_msg = str(e)
        if "AccessDenied" in error_msg or "UnauthorizedOperation" in error_msg:
            error_msg = "Access denied to AWS Organizations API. Ensure you have the required permissions."
        console.print(
            f"[bold yellow]Warning: Could not fetch AWS Organization accounts: {error_msg}[/bold yellow]"
        )
        return {}, error_msg


def fetch_organization_id(session: boto3.Session) -> str | None:
    """Return this account's Organizations ID (o-xxxx), or None."""
    try:
        org = session.client("organizations").describe_organization()
        org_id = org.get("Organization", {}).get("Id")
        if org_id:
            console.print(f"[green]AWS Organization ID: {org_id}[/green]")
        return org_id
    except Exception:
        return None


def fetch_trusted_accounts(
    session: boto3.Session,
    trusted_accounts_file: str = DEFAULT_TRUSTED_ACCOUNTS_FILE,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Fetch trusted AWS accounts from both local YAML file and AWS Organizations."""
    trusted_accounts: dict[str, dict[str, Any]] = {}

    org_accounts, org_error = fetch_org_accounts(session)
    trusted_accounts.update(org_accounts)

    try:
        if not os.path.exists(trusted_accounts_file):
            console.print(
                "[yellow]No trusted accounts file found. Using only AWS Organization accounts.[/yellow]"
            )
            return trusted_accounts, org_error

        with open(trusted_accounts_file, "r") as fh:
            trusted_data = yaml.safe_load(fh) or []

        yaml_count = 0
        for entity in trusted_data:
            if not isinstance(entity, dict):
                continue
            for raw_id in entity.get("accounts", []):
                account_id = str(raw_id).strip()
                if len(account_id) != 12 or not account_id.isdigit():
                    continue
                trusted_accounts[account_id] = {
                    "name": entity.get("name", "Internal"),
                    "type": "trusted",
                    "description": entity.get("description", ""),
                    "source": "yaml_file",
                }
                yaml_count += 1

        console.print(
            f"[green]Loaded {yaml_count} trusted AWS accounts from YAML file[/green]"
        )
        if org_error and yaml_count:
            org_error = (
                f"{org_error} Using trusted_accounts.yaml instead "
                f"({yaml_count} account(s))."
            )
        elif org_error and yaml_count == 0:
            console.print(
                "[yellow]Member accounts cannot list Organizations. "
                "Copy trusted_accounts.yaml.sample to trusted_accounts.yaml.[/yellow]"
            )
        return trusted_accounts, org_error

    except Exception as e:
        console.print(
            f"[bold yellow]Warning: Could not load trusted accounts from YAML file: {e}[/bold yellow]"
        )
        return trusted_accounts, org_error


def get_account_aliases(session: boto3.Session) -> dict[str, str]:
    """Get AWS account alias for the current account."""
    try:
        sts_client = session.client("sts")
        iam_client = session.client("iam")

        current_account_id = sts_client.get_caller_identity()["Account"]

        aliases: dict[str, str] = {}
        try:
            response = iam_client.list_account_aliases()
            if response["AccountAliases"]:
                aliases[current_account_id] = response["AccountAliases"][0]
            else:
                aliases[current_account_id] = current_account_id
        except Exception:
            aliases[current_account_id] = current_account_id

        return aliases

    except Exception as e:
        console.print(
            f"[bold yellow]Warning: Could not get account aliases: {e}[/bold yellow]"
        )
        return {}


def _owner_label(
    account_id: str,
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
) -> str:
    if not account_id:
        return ""
    if account_id in org_accounts:
        return f"{account_id} ({org_accounts[account_id]['name']})"
    if account_id in account_aliases:
        return f"{account_id} ({account_aliases[account_id]})"
    return account_id


def grant_collect_context(
    *,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    current_account_id: str,
    our_organization_id: str | None,
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "account_to_vendor": account_to_vendor,
        "trusted_accounts": trusted_accounts,
        "current_account_id": current_account_id,
        "our_organization_id": our_organization_id,
        "owner_account": current_account_id,
        "owner_label": _owner_label(current_account_id, account_aliases, org_accounts),
    }


def collect_iam_role_grants(
    session: boto3.Session,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Expand IAM role trust policies into grant rows."""
    console.print("[bold blue]Checking IAM role trust policies...[/bold blue]")
    grants: list[dict[str, Any]] = []
    try:
        iam_client = session.client("iam")
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                role_arn = role.get("Arn") or role_name
                grants.extend(
                    grants_from_policy_document(
                        role.get("AssumeRolePolicyDocument") or {},
                        resource=role_arn,
                        resource_type="AWS::IAM::Role",
                        mechanism="trust_policy",
                        region="global",
                        default_actions=["sts:AssumeRole"],
                        trusted_accounts=kwargs["trusted_accounts"],
                        account_to_vendor=kwargs["account_to_vendor"],
                        current_account_id=kwargs["current_account_id"],
                        owner_account=kwargs["owner_account"],
                        owner_label=kwargs["owner_label"],
                        our_organization_id=kwargs["our_organization_id"],
                    )
                )
        console.print(f"[green]IAM role grants: {len(grants)}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error checking IAM role trust policies: {e}[/bold red]")
    return grants


def _bucket_is_effectively_public(s3_client: Any, bucket_name: str) -> bool | None:
    """GetBucketPolicyStatus.IsPublic, or None if the call fails."""
    try:
        status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        return bool((status.get("PolicyStatus") or {}).get("IsPublic"))
    except ClientError:
        return None
    except (BotoCoreError, Exception):
        return None


def collect_s3_bucket_grants(
    session: boto3.Session,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Expand S3 bucket policies into grant rows.

    Public ``Principal: "*"`` rows are checked with GetBucketPolicyStatus so
    Block Public Access is not reported as current public access.
    """
    console.print("[bold blue]Checking S3 bucket policies...[/bold blue]")
    grants: list[dict[str, Any]] = []
    try:
        s3_client = session.client("s3")
        for bucket in s3_client.list_buckets().get("Buckets", []):
            bucket_name = bucket["Name"]
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_document = json.loads(policy_response["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                console.print(
                    f"[yellow]Warning: Could not check policy for bucket {bucket_name}: "
                    f"{e.response['Error']['Message']}[/yellow]"
                )
                continue
            bucket_grants = grants_from_policy_document(
                policy_document,
                resource=bucket_name,
                resource_type="AWS::S3::Bucket",
                mechanism="s3_bucket_policy",
                region="global",
                trusted_accounts=kwargs["trusted_accounts"],
                account_to_vendor=kwargs["account_to_vendor"],
                current_account_id=kwargs["current_account_id"],
                owner_account=kwargs["owner_account"],
                owner_label=kwargs["owner_label"],
                our_organization_id=kwargs["our_organization_id"],
            )
            if any(g.get("is_public") for g in bucket_grants):
                effectively_public = _bucket_is_effectively_public(s3_client, bucket_name)
                if effectively_public is None:
                    console.print(
                        f"[yellow]Warning: GetBucketPolicyStatus failed for "
                        f"{bucket_name}; treating Allow * as currently public[/yellow]"
                    )
                for grant in bucket_grants:
                    apply_s3_effective_public(grant, effectively_public)
            grants.extend(bucket_grants)
        console.print(f"[green]S3 bucket policy grants: {len(grants)}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error checking S3 bucket policies: {e}[/bold red]")
    return grants


def _ram_permission_actions(
    ram_client: Any, share_arn: str, cache: dict[tuple[str, str], list[str]]
) -> list[str]:
    actions: list[str] = []
    try:
        perms = ram_client.list_resource_share_permissions(resourceShareArn=share_arn)
    except ClientError:
        return actions
    for perm in perms.get("permissions", []):
        arn = perm.get("arn") or ""
        version = str(perm.get("version") or "")
        key = (arn, version)
        if key not in cache:
            try:
                detail = ram_client.get_permission(
                    permissionArn=arn,
                    permissionVersion=int(version) if version.isdigit() else 1,
                )
                doc = (detail.get("permission") or {}).get("permission")
                cache[key] = actions_from_ram_permission(doc)
            except (ClientError, TypeError, ValueError):
                cache[key] = []
        actions.extend(cache[key])
    return list(dict.fromkeys(actions))


def _collect_ram_in_region(
    session: boto3.Session,
    region: str,
    kwargs: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], str | None]:
    grants: list[dict[str, Any]] = []
    try:
        ram = session.client("ram", region_name=region, config=AA_CLIENT_CONFIG)
        principals_by_share: dict[str, list[str]] = {}
        resources_by_share: dict[str, list[str]] = {}
        assoc_pager = ram.get_paginator("get_resource_share_associations")
        for page in assoc_pager.paginate(associationType="PRINCIPAL"):
            for assoc in page.get("resourceShareAssociations", []):
                if assoc.get("status") != "ASSOCIATED":
                    continue
                entity = assoc.get("associatedEntity") or ""
                share = assoc.get("resourceShareArn") or ""
                if not entity or not share:
                    continue
                if is_aws_service_principal(entity):
                    continue
                principals_by_share.setdefault(share, []).append(entity)
        for page in assoc_pager.paginate(associationType="RESOURCE"):
            for assoc in page.get("resourceShareAssociations", []):
                if assoc.get("status") != "ASSOCIATED":
                    continue
                entity = assoc.get("associatedEntity") or ""
                share = assoc.get("resourceShareArn") or ""
                if entity and share:
                    resources_by_share.setdefault(share, []).append(entity)

        perm_cache: dict[tuple[str, str], list[str]] = {}
        for share_arn, principals in principals_by_share.items():
            resources = resources_by_share.get(share_arn) or []
            if not resources:
                continue
            actions = _ram_permission_actions(ram, share_arn, perm_cache)
            for resource_arn in resources:
                for principal in principals:
                    parsed = parse_principal_value(
                        "AWS",
                        principal,
                        our_organization_id=kwargs["our_organization_id"],
                    )
                    grant = grant_from_parsed_principal(
                        parsed,
                        statement=None,
                        resource=resource_arn,
                        resource_type="AWS::RAM::ResourceShare",
                        mechanism="ram_share",
                        trusted_accounts=kwargs["trusted_accounts"],
                        account_to_vendor=kwargs["account_to_vendor"],
                        current_account_id=kwargs["current_account_id"],
                        region=region,
                        owner_account=kwargs["owner_account"],
                        owner_label=kwargs["owner_label"],
                        actions=actions,
                    )
                    if grant:
                        grants.append(grant)
        return region, grants, None
    except ClientError as e:
        return region, [], e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:
        return region, [], str(e)


def _run_regional_collector(
    session: boto3.Session,
    regions: list[str],
    worker: Any,
    kwargs: dict[str, Any],
    *,
    warning_prefix: str,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Fan out a per-region worker. Failures are returned, not swallowed into coverage."""
    grants: list[dict[str, Any]] = []
    failures: list[tuple[str, str]] = []
    if not regions:
        return grants, failures
    workers = min(AA_MAX_WORKERS, max(1, len(regions)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(worker, session, region, kwargs) for region in regions
        ]
        for future in as_completed(futures):
            region, region_grants, error = future.result()
            if error:
                console.print(
                    f"[yellow]Warning: {warning_prefix} in {region}: {error}[/yellow]"
                )
                failures.append((region, error))
                continue
            grants.extend(region_grants)
    order = {region: i for i, region in enumerate(regions)}
    failures.sort(key=lambda item: order.get(item[0], 10_000))
    return grants, failures


def collect_ram_grants(
    session: boto3.Session,
    regions: list[str],
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """RAM resource shares: join ASSOCIATED principals to ASSOCIATED resources.

    Does not use ``list-resources --principal`` (that API ignores the role name).
    Pending invitations (ASSOCIATING) are skipped — they are not access yet.
    """
    console.print(
        f"[bold blue]Checking RAM resource shares in {len(regions)} region(s)...[/bold blue]"
    )
    grants, failures = _run_regional_collector(
        session, regions, _collect_ram_in_region, kwargs, warning_prefix="RAM"
    )
    console.print(f"[green]RAM share grants: {len(grants)}[/green]")
    return grants, failures


def _ami_grants_for_image(
    ec2: Any,
    image: dict[str, Any],
    region: str,
    kwargs: dict[str, Any],
) -> list[dict[str, Any]]:
    image_id = image.get("ImageId") or ""
    grants: list[dict[str, Any]] = []
    try:
        attr = ec2.describe_image_attribute(
            ImageId=image_id, Attribute="launchPermission"
        )
    except ClientError:
        return grants
    for perm in attr.get("LaunchPermissions", []):
        if (perm.get("Group") or "").lower() == "all":
            parsed = parse_principal_value("Wildcard", "*")
        elif perm.get("UserId"):
            parsed = parse_principal_value(
                "AWS", perm["UserId"], our_organization_id=kwargs["our_organization_id"]
            )
        elif perm.get("OrganizationArn"):
            parsed = parse_principal_value(
                "AWS",
                perm["OrganizationArn"],
                our_organization_id=kwargs["our_organization_id"],
            )
        elif perm.get("OrganizationalUnitArn"):
            parsed = parse_principal_value(
                "AWS",
                perm["OrganizationalUnitArn"],
                our_organization_id=kwargs["our_organization_id"],
            )
        else:
            continue
        grant = grant_from_parsed_principal(
            parsed,
            statement=None,
            resource=image_id,
            resource_type="AWS::EC2::Image",
            mechanism="ami_launch_permission",
            trusted_accounts=kwargs["trusted_accounts"],
            account_to_vendor=kwargs["account_to_vendor"],
            current_account_id=kwargs["current_account_id"],
            region=region,
            owner_account=kwargs["owner_account"],
            owner_label=kwargs["owner_label"],
            actions=["ec2:RunInstances"],
        )
        if grant:
            grants.append(grant)
    return grants


def _collect_ami_in_region(
    session: boto3.Session,
    region: str,
    kwargs: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], str | None]:
    grants: list[dict[str, Any]] = []
    try:
        ec2 = session.client("ec2", region_name=region, config=AA_CLIENT_CONFIG)
        images: list[dict[str, Any]] = []
        pager = ec2.get_paginator("describe_images")
        for page in pager.paginate(Owners=["self"]):
            images.extend(page.get("Images", []))
        # Attribute reads are one-image-at-a-time; bound concurrency per region.
        workers = min(8, max(1, len(images)))
        if not images:
            return region, [], None
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_ami_grants_for_image, ec2, image, region, kwargs)
                for image in images
            ]
            for future in as_completed(futures):
                grants.extend(future.result())
        return region, grants, None
    except ClientError as e:
        return region, [], e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:
        return region, [], str(e)


def collect_ami_grants(
    session: boto3.Session,
    regions: list[str],
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """AMI launch permissions. OrganizationArn is not assumed internal."""
    console.print(
        f"[bold blue]Checking AMI launch permissions in {len(regions)} region(s)...[/bold blue]"
    )
    grants, failures = _run_regional_collector(
        session, regions, _collect_ami_in_region, kwargs, warning_prefix="AMIs"
    )
    console.print(f"[green]AMI launch-permission grants: {len(grants)}[/green]")
    return grants, failures


def _collect_ssm_in_region(
    session: boto3.Session,
    region: str,
    kwargs: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], str | None]:
    grants: list[dict[str, Any]] = []
    try:
        ssm = session.client("ssm", region_name=region, config=AA_CLIENT_CONFIG)
        pager = ssm.get_paginator("list_documents")
        names: list[str] = []
        for page in pager.paginate(Filters=[{"Key": "Owner", "Values": ["Self"]}]):
            for doc in page.get("DocumentIdentifiers", []):
                name = doc.get("Name")
                if name:
                    names.append(name)
        for name in names:
            try:
                perm = ssm.describe_document_permission(
                    Name=name, PermissionType="Share"
                )
            except ClientError:
                continue
            for acct in perm.get("AccountIds") or []:
                if not isinstance(acct, str):
                    continue
                if acct.lower() == "all":
                    parsed = parse_principal_value("Wildcard", "*")
                else:
                    parsed = parse_principal_value(
                        "AWS", acct, our_organization_id=kwargs["our_organization_id"]
                    )
                grant = grant_from_parsed_principal(
                    parsed,
                    statement=None,
                    resource=name,
                    resource_type="AWS::SSM::Document",
                    mechanism="ssm_document_share",
                    trusted_accounts=kwargs["trusted_accounts"],
                    account_to_vendor=kwargs["account_to_vendor"],
                    current_account_id=kwargs["current_account_id"],
                    region=region,
                    owner_account=kwargs["owner_account"],
                    owner_label=kwargs["owner_label"],
                    actions=["ssm:GetDocument"],
                )
                if grant:
                    grants.append(grant)
        return region, grants, None
    except ClientError as e:
        return region, [], e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:
        return region, [], str(e)


def collect_ssm_document_grants(
    session: boto3.Session,
    regions: list[str],
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """SSM document share attributes (account-id lists, including public ``all``)."""
    console.print(
        f"[bold blue]Checking SSM document shares in {len(regions)} region(s)...[/bold blue]"
    )
    grants, failures = _run_regional_collector(
        session, regions, _collect_ssm_in_region, kwargs, warning_prefix="SSM"
    )
    console.print(f"[green]SSM document share grants: {len(grants)}[/green]")
    return grants, failures


def _list_service_specific_credentials(iam_client: Any) -> list[dict[str, Any]]:
    """List SSC for every user. Prefer unfiltered AllUsers; fall back per service."""
    creds: list[dict[str, Any]] = []

    def _pages(**extra: Any) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        marker = None
        while True:
            kwargs: dict[str, Any] = {"AllUsers": True, **extra}
            if marker:
                kwargs["Marker"] = marker
            resp = iam_client.list_service_specific_credentials(**kwargs)
            collected.extend(resp.get("ServiceSpecificCredentials") or [])
            if not resp.get("IsTruncated"):
                return collected
            marker = resp.get("Marker")

    try:
        return _pages()
    except ClientError:
        for service in SERVICE_SPECIFIC_CREDENTIAL_SERVICES:
            try:
                creds.extend(_pages(ServiceName=service))
            except ClientError as e:
                console.print(
                    f"[yellow]Warning: service-specific credentials for "
                    f"{service}: {e.response['Error']['Message']}[/yellow]"
                )
        return creds


def collect_service_specific_credential_grants(
    session: boto3.Session,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """IAM service-specific credentials / long-lived API keys (Bedrock, CW, …)."""
    console.print("[bold blue]Checking IAM service-specific credentials...[/bold blue]")
    grants: list[dict[str, Any]] = []
    try:
        iam = session.client("iam")
        for cred in _list_service_specific_credentials(iam):
            user = cred.get("UserName") or ""
            service = cred.get("ServiceName") or ""
            status = cred.get("Status") or "Active"
            expiration = cred.get("ExpirationDate")
            never = expiration is None
            grants.append(
                empty_grant(
                    resource=user,
                    resource_type="AWS::IAM::User",
                    principal=service,
                    principal_kind="credential",
                    principal_label=f"{user} → {service}",
                    mechanism="service_specific_credential",
                    region="global",
                    classification="unknown",
                    never_expires=never and status == "Active",
                    credential_status=status,
                    actions=[service],
                    owner_account=kwargs["current_account_id"],
                    owner_label=kwargs["owner_label"],
                )
            )
        console.print(
            f"[green]Service-specific credentials: {len(grants)}[/green]"
        )
    except Exception as e:
        console.print(
            f"[bold red]Error listing service-specific credentials: {e}[/bold red]"
        )
    return grants


def collect_optional_scanners(
    session: boto3.Session,
    args: argparse.Namespace,
    regions: list[str],
    kwargs: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, str]]]:
    """RAM / AMI / SSM / credentials collectors shared by both backends."""
    grants: list[dict[str, Any]] = []
    scanned: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    def _maybe(flag: str, surface: str, runner: Any) -> None:
        if getattr(args, flag):
            skipped.append({"surface": surface, "detail": f"--{flag.replace('_', '-')}"})
            return
        if not regions and flag in ("skip_ram", "skip_ami", "skip_ssm"):
            skipped.append(
                {
                    "surface": surface,
                    "detail": "No region configured; pass --region / --regions / --all-regions",
                }
            )
            return
        region_grants, failures = runner()
        grants.extend(region_grants)
        failed_ids = {region for region, _ in failures}
        ok_regions = [region for region in regions if region not in failed_ids]
        if ok_regions:
            scanned.append({"surface": surface, "detail": ", ".join(ok_regions)})
        for region, error in failures:
            skipped.append(
                {
                    "surface": f"{surface} ({region})",
                    "detail": error,
                }
            )

    _maybe(
        "skip_ram",
        "RAM resource shares",
        lambda: collect_ram_grants(session, regions, **kwargs),
    )
    _maybe(
        "skip_ami",
        "AMI launch permissions",
        lambda: collect_ami_grants(session, regions, **kwargs),
    )
    _maybe(
        "skip_ssm",
        "SSM document shares",
        lambda: collect_ssm_document_grants(session, regions, **kwargs),
    )
    if args.skip_credentials:
        skipped.append(
            {
                "surface": "IAM service-specific credentials",
                "detail": "--skip-credentials",
            }
        )
    else:
        grants.extend(collect_service_specific_credential_grants(session, **kwargs))
        scanned.append(
            {
                "surface": "IAM service-specific credentials",
                "detail": "account-wide (CodeCommit, Keyspaces, Bedrock, CloudWatch, Claude)",
            }
        )
    return grants, scanned, skipped


def _report_filename(
    output_dir: str, identity_slug: str, extension: str
) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(
        output_dir, f"trustline_report_{identity_slug}_{timestamp}.{extension}"
    )


def _coverage_markdown(coverage: dict[str, Any]) -> str:
    lines = ["## Coverage (appendix)\n"]
    lines.append(
        "A green leftover list only covers **scanned** surfaces. "
        "This section is last on purpose — the inventory is the work list.\n"
    )
    backend = coverage.get("backend", "")
    if backend:
        lines.append(f"- Backend: `{backend}`\n")
    if coverage.get("regions"):
        lines.append(
            f"- Regions: `{', '.join(coverage['regions'])}`"
            + (" (all enabled)" if coverage.get("all_regions") else "")
            + "\n"
        )
    for note in coverage.get("analyzer_notes") or []:
        lines.append(f"- {note}\n")
    lines.append("\n### Scanned\n\n")
    scanned = coverage.get("scanned") or []
    if scanned:
        lines.append("| Surface | Detail |\n|---------|--------|\n")
        for item in scanned:
            lines.append(f"| {item['surface']} | {item['detail']} |\n")
    else:
        lines.append("Nothing was scanned.\n")
    lines.append("\n### Not scanned\n\n")
    lines.append("| Surface | Why |\n|---------|-----|\n")
    for item in coverage.get("not_scanned") or []:
        lines.append(f"| {item['surface']} | {item['detail']} |\n")
    lines.append("\n")
    return "".join(lines)


def _grant_resource_name(grant: dict[str, Any]) -> str:
    return grant_resource_label(grant)


def _party_resource_summary(party: dict[str, Any], *, limit: int = 6) -> str:
    items = party.get("grants") or []
    if items:
        names = [grant_resource_label(g) for g in items]
    else:
        names = [grant_resource_label({"resource": r}) for r in (party.get("resources") or []) if r]
    if len(names) > limit:
        return ", ".join(names[:limit]) + f" +{len(names) - limit} more"
    return ", ".join(names) or "—"


def _inventory_markdown(grants: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    parties = parties_from_grants(grants)
    blocked = [g for g in grants if g.get("blocked_by_bpa")]
    lines = [
        "## External access (by principal)\n\n",
        "One row per external party. Account IDs are looked up in "
        "[fwd:cloudsec known AWS accounts](https://github.com/fwdcloudsec/known_aws_accounts). "
        "Unresolved means the ID was not in that dataset, your YAML, or Organizations.\n\n",
    ]
    if not parties:
        lines.append("No current external access in scanned surfaces.\n\n")
    else:
        lines.append(
            "| Principal | Name source | Classification | Grants | Mechanisms | Resources |\n"
            "|-----------|-------------|----------------|--------|------------|-----------|\n"
        )
        for party in parties:
            lines.append(
                f"| {party['name']} | {party['name_source_label']} | "
                f"{party['classification']} | {party['grant_count']} | "
                f"{', '.join(party['mechanisms'])} | {_party_resource_summary(party)} |\n"
            )
        lines.append("\n")
    return "".join(lines), blocked


def generate_markdown_report(
    grants: list[dict[str, Any]],
    coverage: dict[str, Any],
    *,
    account_aliases: dict[str, str],
    org_error: str | None = None,
    output_dir: str = ".",
    identity_slug: str | None = None,
    identity_label: str | None = None,
) -> str:
    """Write a report: inventory by principal, then leftover flags, coverage last."""
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)
    slug = identity_slug or current_account_id
    label = identity_label or f"{current_account_id} ({current_account_alias})"
    report_file = _report_filename(output_dir, slug, "md")
    totals = totals_from_grants(grants)
    parties = parties_from_grants(grants)

    def _rows(predicate) -> list[dict[str, Any]]:
        return [g for g in grants if predicate(g)]

    inventory, blocked = _inventory_markdown(grants)

    with open(report_file, "w") as f:
        f.write("# AWS Trustline - Access Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Account/scope: {label}\n\n")
        if org_error:
            f.write("## AWS Organizations Access\n\n")
            f.write(f"Could not access AWS Organizations API: {org_error}\n\n")
        f.write("## Summary\n\n")
        f.write(
            f"- External parties: {len(parties)}\n"
            f"- Trusted: {totals['trusted']}\n"
            f"- Known vendors: {totals['vendors']}\n"
            f"- Federated (OIDC/SAML/Cognito): {totals['federated']}\n"
            f"- Not in known_aws_accounts: {totals['unknown']}\n"
            f"- Public: {totals['public']}\n"
            f"- Blocked by Block Public Access: {totals['blocked_public']}\n"
            f"- Missing ExternalId: {totals['missing_external_id']}\n"
            f"- OIDC missing sub/aud: {totals['missing_oidc_subject']}\n"
            f"- Never-expiring service credentials: {totals['never_expires']}\n"
            f"- Total grants: {totals['findings']}\n\n"
        )
        f.write(inventory)

        def write_grant_table(title: str, items: list[dict[str, Any]]) -> None:
            if not items:
                return
            f.write(f"## {title}\n\n")
            f.write("| Resource | Principal | Mechanism | Classification |\n")
            f.write("|----------|-----------|-----------|----------------|\n")
            for g in items:
                f.write(
                    f"| {g.get('resource', '')} | {g.get('principal_label') or g.get('principal')} "
                    f"| {MECHANISM_LABELS.get(g.get('mechanism', ''), g.get('mechanism', ''))} "
                    f"| {g.get('classification')} |\n"
                )
            f.write("\n")

        write_grant_table(
            "OIDC trusts missing sub/aud conditions",
            _rows(lambda g: g.get("missing_oidc_subject")),
        )
        write_grant_table(
            "IAM roles missing ExternalId condition",
            _rows(lambda g: g.get("missing_external_id")),
        )
        write_grant_table(
            "Never-expiring service-specific credentials",
            _rows(lambda g: g.get("never_expires")),
        )
        write_grant_table(
            "Policy allows everyone; Block Public Access denies it",
            blocked,
        )
        f.write(_coverage_markdown(coverage))
    return report_file


def display_grants(
    grants: list[dict[str, Any]],
    coverage: dict[str, Any],
    account_aliases: dict[str, str],
) -> None:
    """Render the principal inventory, then leftover flags."""
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)
    totals = totals_from_grants(grants)
    parties = parties_from_grants(grants)

    console.print(
        f"\n[cyan]Analyzing:[/cyan] {current_account_id} ({current_account_alias})\n"
    )

    if parties:
        table = Table(
            title=f"External access by principal ({len(parties)})",
            box=box.ROUNDED,
        )
        table.add_column("Principal", style="cyan", overflow="fold")
        table.add_column("Name source", style="blue", overflow="fold")
        table.add_column("Class", style="green")
        table.add_column("Grants", justify="right")
        table.add_column("Resources", overflow="fold")
        for party in parties[:50]:
            row = (
                party["name"],
                party["name_source_label"],
                party["classification"],
                str(party["grant_count"]),
                _party_resource_summary(party),
            )
            if party["classification"] == "unknown":
                table.add_row(*row, style="yellow")
            else:
                table.add_row(*row)
        if len(parties) > 50:
            table.add_row("…", f"+{len(parties) - 50} more", "", "", "")
        console.print(table)

    def _table(title: str, items: list[dict[str, Any]], color: str) -> None:
        if not items:
            return
        table = Table(title=f"{title} ({len(items)})", box=box.ROUNDED)
        table.add_column("Resource", style="cyan", overflow="fold")
        table.add_column("Principal", style=color, overflow="fold")
        table.add_column("Mechanism", style="blue")
        table.add_column("Classification", style="green")
        for g in items[:50]:
            table.add_row(
                _grant_resource_name(g),
                g.get("principal_label") or g.get("principal") or "-",
                MECHANISM_LABELS.get(g.get("mechanism") or "", g.get("mechanism") or "-"),
                g.get("classification") or "-",
            )
        if len(items) > 50:
            table.add_row("…", f"+{len(items) - 50} more", "", "")
        console.print(table)

    _table(
        "OIDC missing sub/aud",
        [g for g in grants if g.get("missing_oidc_subject")],
        "red",
    )
    _table(
        "Missing ExternalId",
        [g for g in grants if g.get("missing_external_id")],
        "red",
    )
    _table(
        "Never-expiring credentials",
        [g for g in grants if g.get("never_expires")],
        "red",
    )
    _table(
        "Blocked by Block Public Access",
        [g for g in grants if g.get("blocked_by_bpa")],
        "yellow",
    )

    console.print(
        Panel(
            f"[bold]Summary:[/bold]\n"
            f"[cyan]External parties:[/cyan] {len(parties)}\n"
            f"[green]Trusted:[/green] {totals['trusted']}\n"
            f"[cyan]Known vendors:[/cyan] {totals['vendors']}\n"
            f"[blue]Federated:[/blue] {totals['federated']}\n"
            f"[yellow]Not in known_aws_accounts:[/yellow] {totals['unknown']}\n"
            f"[red]Public:[/red] {totals['public']}\n"
            f"[dim]Blocked by BPA:[/dim] {totals['blocked_public']}\n"
            f"[red]Missing ExternalId:[/red] {totals['missing_external_id']}\n"
            f"[red]OIDC missing sub/aud:[/red] {totals['missing_oidc_subject']}\n"
            f"[red]Never-expiring credentials:[/red] {totals['never_expires']}\n"
            f"[bold]Total grants:[/bold] {totals['findings']}",
            title="AWS Trustline Results",
            box=box.ROUNDED,
        )
    )
    scanned_bit = ", ".join(item["surface"] for item in (coverage.get("scanned") or [])[:6])
    aa_note = ""
    if coverage.get("backend") == "access_analyzer":
        aa_note = " Analyzer ACTIVE is not scan-complete."
    console.print(
        Panel(
            f"[dim]Scanned:[/dim] {scanned_bit or '—'}\n"
            f"[dim]Not scanned:[/dim] {len(coverage.get('not_scanned') or [])} surfaces "
            f"(see report appendix).{aa_note}",
            title="Coverage",
            box=box.ROUNDED,
        )
    )
    if coverage.get("backend") != "access_analyzer":
        for note in coverage.get("analyzer_notes") or []:
            console.print(f"[yellow]{note}[/yellow]")


def resolve_regions(session: boto3.Session, args: argparse.Namespace) -> list[str]:
    """Resolve the ordered list of regions for the Access Analyzer backend.

    Precedence: ``--regions`` (comma-separated) > ``--all-regions`` (enumerated
    via ``ec2:DescribeRegions``) > the session's default region.
    """
    if getattr(args, "regions", None):
        raw = args.regions
        regions = [r.strip() for r in raw.split(",") if r.strip()]
        if not regions:
            raise ValueError("--regions was provided but parsed to an empty list")
        return regions

    if getattr(args, "all_regions", False):
        # describe_regions is regional; pin to a stable region so the call
        # works even when the session has no default region configured.
        bootstrap_region = session.region_name or "us-east-1"
        ec2 = session.client(
            "ec2", region_name=bootstrap_region, config=AA_CLIENT_CONFIG
        )
        try:
            response = ec2.describe_regions(AllRegions=False)
        except ClientError as e:
            raise RuntimeError(
                f"Could not enumerate regions via ec2:DescribeRegions: "
                f"{e.response['Error']['Message']}"
            ) from e
        regions = sorted(r["RegionName"] for r in response.get("Regions", []))
        if not regions:
            raise RuntimeError("ec2:DescribeRegions returned no enabled regions")
        return regions

    default_region = session.region_name
    if not default_region:
        raise ValueError(
            "No region configured. Pass --region, --regions, or --all-regions, "
            "or set AWS_DEFAULT_REGION."
        )
    return [default_region]


def _list_analyzers_in_region(
    session: boto3.Session,
    region: str,
    allowed_types: set[str],
) -> tuple[str, list[dict[str, str]] | None, str | None]:
    """Worker for parallel analyzer discovery. Returns (region, candidates, error_msg)."""
    try:
        client = session.client(
            "accessanalyzer", region_name=region, config=AA_CLIENT_CONFIG
        )
        paginator = client.get_paginator("list_analyzers")
        candidates: list[dict[str, str]] = []
        for page in paginator.paginate():
            for analyzer in page.get("analyzers", []):
                if analyzer.get("status") != "ACTIVE":
                    continue
                if analyzer.get("type") not in allowed_types:
                    continue
                candidates.append(
                    {
                        "arn": analyzer["arn"],
                        "type": analyzer["type"],
                        "name": analyzer.get("name", ""),
                        "created_at": str(analyzer.get("createdAt") or ""),
                    }
                )
        return region, candidates, None
    except ClientError as e:
        return region, None, e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:  # network / timeout / endpoint
        return region, None, str(e)


def find_external_analyzers(
    session: boto3.Session,
    regions: list[str],
    scope: str,
) -> dict[str, dict[str, str]]:
    """Discover ACTIVE external IAM Access Analyzers in each region.

    ``scope`` is one of ``account``, ``organization`` or ``auto``:

    - ``account`` keeps only analyzers of type ``ACCOUNT``.
    - ``organization`` keeps only analyzers of type ``ORGANIZATION``.
    - ``auto`` keeps both but prefers ``ACCOUNT`` per region (this-account
      inventory). ORGANIZATION is used only when no ACCOUNT analyzer exists
      in that region.

    Returns a ``{region: {"arn": ..., "type": ..., "name": ...}}`` mapping.
    Regions with no matching analyzer are omitted; the caller is expected to
    warn or fall back as appropriate. Per-region calls run in parallel under
    short timeouts so one unreachable region (transient outage, etc.) cannot
    block the whole run.
    """
    if scope not in ("account", "organization", "auto"):
        raise ValueError(f"Invalid scope: {scope!r}")

    allowed_types: set[str]
    if scope == "account":
        allowed_types = {"ACCOUNT"}
    elif scope == "organization":
        allowed_types = {"ORGANIZATION"}
    else:
        allowed_types = set(EXTERNAL_ANALYZER_TYPES)

    discovered: dict[str, dict[str, str]] = {}

    workers = min(AA_MAX_WORKERS, max(1, len(regions)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_list_analyzers_in_region, session, r, allowed_types): r
            for r in regions
        }
        for future in as_completed(futures):
            region, candidates, error = future.result()
            if error is not None:
                console.print(
                    f"[yellow]Warning: Could not list analyzers in {region}: "
                    f"{error}[/yellow]"
                )
                continue
            if not candidates:
                continue

            chosen = choose_external_analyzer(candidates, scope)
            if chosen is None:
                continue
            discovered[region] = chosen

    return discovered


def _count_findings_in_region(
    session: boto3.Session,
    region: str,
    analyzer: dict[str, str],
) -> tuple[str, int, str | None, str | None]:
    """Return (region, count, newest_analyzed_at, error)."""
    try:
        client = session.client(
            "accessanalyzer", region_name=region, config=AA_CLIENT_CONFIG
        )
        paginator = client.get_paginator("list_findings")
        count = 0
        newest: datetime | None = None
        for page in paginator.paginate(
            analyzerArn=analyzer["arn"],
            filter={"status": {"eq": ["ACTIVE"]}},
        ):
            for raw in page.get("findings", []):
                count += 1
                analyzed = raw.get("analyzedAt")
                if analyzed is None:
                    continue
                if not isinstance(analyzed, datetime):
                    try:
                        analyzed = datetime.fromisoformat(str(analyzed).replace("Z", "+00:00"))
                    except ValueError:
                        continue
                if newest is None or analyzed > newest:
                    newest = analyzed
        newest_s = newest.isoformat() if newest else None
        return region, count, newest_s, None
    except ClientError as e:
        return region, 0, None, e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:
        return region, 0, None, str(e)


def wait_for_analyzer_findings(
    session: boto3.Session,
    analyzers: dict[str, dict[str, str]],
    timeout: int,
    interval: int = 15,
) -> list[str]:
    """Poll ACTIVE finding counts until they stabilize or ``timeout`` seconds elapse.

    Analyzer status ACTIVE is not 'scan finished'. There is no API field that
    separates the two, so we wait until counts stop changing for two intervals.
    """
    deadline = time.time() + max(1, timeout)
    last_counts: dict[str, int] | None = None
    stable_rounds = 0
    notes: list[str] = []
    console.print(
        f"[bold blue]Waiting up to {timeout}s for Access Analyzer findings to "
        f"stabilize (ACTIVE ≠ complete)...[/bold blue]"
    )
    while time.time() < deadline:
        counts: dict[str, int] = {}
        analyzed_ats: list[str] = []
        workers = min(AA_MAX_WORKERS, max(1, len(analyzers)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_count_findings_in_region, session, region, analyzer): region
                for region, analyzer in analyzers.items()
            }
            for future in as_completed(futures):
                region, count, newest, error = future.result()
                if error:
                    console.print(
                        f"[yellow]Warning: wait poll in {region}: {error}[/yellow]"
                    )
                    continue
                counts[region] = count
                if newest:
                    analyzed_ats.append(newest)
        total = sum(counts.values())
        console.print(
            f"[dim]Analyzer poll: {total} ACTIVE finding(s) across "
            f"{len(counts)} region(s)[/dim]"
        )
        if last_counts is not None and counts == last_counts:
            stable_rounds += 1
            if stable_rounds >= 2:
                if analyzed_ats:
                    notes.append(
                        f"Newest finding analyzedAt after wait: {max(analyzed_ats)}"
                    )
                else:
                    notes.append(
                        "Analyzer reported 0 findings after wait. If it was created "
                        "recently, the first scan can take ~20 minutes."
                    )
                return notes
        else:
            stable_rounds = 0
        last_counts = counts
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
    notes.append(
        f"Waited {timeout}s without a stable finding count. Report may be incomplete."
    )
    return notes


def _assume_role_policy_document(iam_client: Any, role_name: str) -> dict[str, Any] | None:
    """Live AssumeRolePolicyDocument, or None if GetRole fails."""
    try:
        role = iam_client.get_role(RoleName=role_name)
        doc = (role.get("Role") or {}).get("AssumeRolePolicyDocument")
        if isinstance(doc, str):
            return json.loads(unquote(doc))
        if isinstance(doc, dict):
            return doc
    except (ClientError, BotoCoreError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return None


def enrich_aa_iam_role_conditions(
    session: boto3.Session,
    grants: list[dict[str, Any]],
    current_account_id: str,
) -> list[str]:
    """Replace AA leftover flags with live trust-policy conditions when possible.

    Access Analyzer often omits Condition. Empty condition is not proof the
    role is missing sub/aud or ExternalId.
    """
    notes: list[str] = []
    skipped = 0
    iam = session.client("iam")
    cache: dict[str, dict[str, Any] | None] = {}
    for grant in grants:
        if grant.get("resource_type") != "AWS::IAM::Role":
            continue
        if grant.get("mechanism") != "access_analyzer":
            continue
        owner = grant.get("resource_owner") or grant.get("owner_account") or ""
        other_account = bool(
            current_account_id and owner and owner != current_account_id
        )
        aa_empty = not flatten_condition_keys(grant.get("condition"))
        if other_account:
            if aa_empty:
                clear_unproven_aa_condition_flags(grant)
                skipped += 1
            continue
        role_name = role_name_from_resource(grant.get("resource") or "")
        if not role_name:
            if aa_empty:
                clear_unproven_aa_condition_flags(grant)
                skipped += 1
            continue
        if role_name not in cache:
            cache[role_name] = _assume_role_policy_document(iam, role_name)
        doc = cache[role_name]
        if not doc:
            if aa_empty:
                clear_unproven_aa_condition_flags(grant)
                skipped += 1
            continue
        apply_live_trust_conditions(grant, doc)
    if skipped:
        notes.append(
            f"OIDC/ExternalId flags omitted for {skipped} Access Analyzer IAM role "
            "finding(s) with no conditions (other-account resource or GetRole "
            "failed). Those flags are not proven leftovers."
        )
    return notes


def _list_findings_in_region(
    session: boto3.Session,
    region: str,
    analyzer: dict[str, str],
    *,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    our_organization_id: str | None = None,
    restrict_to_owner: str | None = None,
) -> tuple[str, list[dict[str, Any]] | None, str | None, int]:
    """Worker for parallel finding collection.

    Returns (region, findings, error, dropped_other_owner_count).
    """
    dropped = 0
    try:
        client = session.client(
            "accessanalyzer", region_name=region, config=AA_CLIENT_CONFIG
        )
        paginator = client.get_paginator("list_findings")
        out: list[dict[str, Any]] = []
        for page in paginator.paginate(
            analyzerArn=analyzer["arn"],
            filter={"status": {"eq": ["ACTIVE"]}},
        ):
            for raw in page.get("findings", []):
                owner = raw.get("resourceOwnerAccount") or ""
                if restrict_to_owner and owner and owner != restrict_to_owner:
                    dropped += 1
                    continue
                grant = _classify_aa_finding(
                    raw,
                    region=region,
                    analyzer_type=analyzer["type"],
                    account_to_vendor=account_to_vendor,
                    trusted_accounts=trusted_accounts,
                    account_aliases=account_aliases,
                    org_accounts=org_accounts,
                    our_organization_id=our_organization_id,
                )
                if grant:
                    out.append(grant)
        return region, out, None, dropped
    except ClientError as e:
        return region, None, e.response["Error"]["Message"], dropped
    except (BotoCoreError, Exception) as e:
        return region, None, str(e), dropped


def collect_access_analyzer_findings(
    session: boto3.Session,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    analyzers: dict[str, dict[str, str]],
    our_organization_id: str | None = None,
    restrict_to_owner: str | None = None,
) -> dict[str, Any]:
    """Collect and classify findings from one or more external analyzers.

    Each finding is a grant row classified as trusted, vendor, unknown,
    public, or federated. IAM roles missing ``sts:ExternalId`` and GitHub/GitLab
    OIDC trusts missing ``sub``/``aud`` are flagged on the row after reading
    the live trust policy when GetRole is allowed.

    ``restrict_to_owner`` drops ORGANIZATION-analyzer findings owned by other
    accounts so a default account-scope scan is not an org dump.
    """
    grants: list[dict[str, Any]] = []
    dropped_other_owners = 0

    console.print(
        f"[bold blue]Collecting findings from {len(analyzers)} analyzer(s) "
        f"in parallel...[/bold blue]"
    )

    workers = min(AA_MAX_WORKERS, max(1, len(analyzers)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _list_findings_in_region,
                session,
                region,
                analyzer,
                account_to_vendor=account_to_vendor,
                trusted_accounts=trusted_accounts,
                account_aliases=account_aliases,
                org_accounts=org_accounts,
                our_organization_id=our_organization_id,
                restrict_to_owner=restrict_to_owner,
            ): region
            for region, analyzer in analyzers.items()
        }
        for future in as_completed(futures):
            region, findings, error, dropped = future.result()
            dropped_other_owners += dropped
            if error is not None:
                console.print(
                    f"[yellow]Warning: Could not list findings in {region}: "
                    f"{error}[/yellow]"
                )
                continue
            for finding in findings or []:
                grants.append(finding)

    before = len(grants)
    grants, dupes = dedupe_access_analyzer_grants(grants)
    findings_by_type = {}
    public_findings = []
    seen_owners = set()
    analyzed_ats = []
    for finding in grants:
        if finding.get("analyzed_at"):
            analyzed_ats.append(str(finding["analyzed_at"]))
        if finding.get("is_public") or finding.get("classification") == "public":
            public_findings.append(finding)
        if finding.get("owner_account") or finding.get("resource_owner"):
            seen_owners.add(
                finding.get("owner_account") or finding.get("resource_owner")
            )
        findings_by_type.setdefault(finding["resource_type"], []).append(finding)

    current_account_id = restrict_to_owner or next(iter(account_aliases), "")
    analyzer_notes = enrich_aa_iam_role_conditions(
        session, grants, current_account_id
    )
    if dupes:
        analyzer_notes.append(
            f"Removed {dupes} duplicate Access Analyzer finding(s) for the same "
            "resource and principal (IAM is global; ACCOUNT + ORGANIZATION "
            f"analyzers overlapped). {before} raw findings, {len(grants)} unique."
        )
    # Recompute leftover lists after GetRole enrichment.
    missing_external_id = [g for g in grants if g.get("missing_external_id")]
    missing_oidc = [g for g in grants if g.get("missing_oidc_subject")]

    totals = totals_from_grants(grants)
    totals["regions"] = len(analyzers)
    totals["owner_accounts"] = len(seen_owners)

    if analyzed_ats:
        analyzer_notes.append(f"Newest finding analyzedAt: {max(analyzed_ats)}")
    else:
        analyzer_notes.append(
            "No analyzedAt timestamps on findings. If analyzers were just created, "
            "ACTIVE does not mean the first scan has finished (~20 minutes)."
        )
    if dropped_other_owners:
        analyzer_notes.append(
            f"Dropped {dropped_other_owners} ORGANIZATION-analyzer finding(s) "
            "owned by other accounts (default inventory is this account; pass "
            "--scope organization for the whole org)."
        )
    if any(a.get("type") == "ORGANIZATION" for a in analyzers.values()) and restrict_to_owner:
        analyzer_notes.append(
            "An ORGANIZATION analyzer was used in at least one region. Sibling "
            "accounts are in that analyzer's zone of trust and will not appear "
            "as external findings there. Prefer an ACCOUNT analyzer per region "
            "for a this-account inventory."
        )

    return {
        "by_resource_type": findings_by_type,
        "missing_external_id": missing_external_id,
        "missing_oidc_subject": missing_oidc,
        "public_findings": public_findings,
        "totals": totals,
        "analyzers": analyzers,
        "owner_accounts": sorted(seen_owners),
        "grants": grants,
        "analyzer_notes": analyzer_notes,
        "dropped_other_owners": dropped_other_owners,
    }


def _classify_aa_finding(
    raw: dict[str, Any],
    *,
    region: str,
    analyzer_type: str,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    our_organization_id: str | None = None,
) -> dict[str, Any] | None:
    """Normalize one Access Analyzer finding into a grant row."""
    resource_type = raw.get("resourceType", "Unknown")
    resource = raw.get("resource", "")
    resource_owner = raw.get("resourceOwnerAccount", "")
    is_public = bool(raw.get("isPublic", False))
    actions = raw.get("action") or []
    condition = raw.get("condition") or {}
    finding_id = raw.get("id", "")
    principal = raw.get("principal") or {}
    analyzed_at = raw.get("analyzedAt")
    analyzed_at_s = str(analyzed_at) if analyzed_at else ""

    parsed: dict[str, Any]
    if is_public:
        parsed = parse_principal_value("Wildcard", "*")
    elif isinstance(principal, dict) and "Federated" in principal:
        parsed = parse_principal_value("Federated", str(principal.get("Federated") or ""))
    elif isinstance(principal, dict) and "CanonicalUser" in principal:
        parsed = parse_principal_value(
            "CanonicalUser", str(principal.get("CanonicalUser") or "")
        )
    elif isinstance(principal, dict) and "AWS" in principal:
        aws_val = principal.get("AWS") or ""
        parsed = parse_principal_value(
            "AWS", str(aws_val), our_organization_id=our_organization_id
        )
    elif isinstance(principal, dict) and principal:
        kind, value = next(iter(principal.items()))
        parsed = parse_principal_value(
            kind if kind in ("AWS", "Federated", "CanonicalUser") else "AWS",
            str(value),
            our_organization_id=our_organization_id,
        )
    else:
        parsed = parse_principal_value("AWS", "")

    current_account_id = next(iter(account_aliases), "") or resource_owner
    grant = grant_from_parsed_principal(
        parsed,
        statement={"Condition": condition} if condition else None,
        resource=resource,
        resource_type=resource_type,
        mechanism="access_analyzer",
        trusted_accounts=trusted_accounts,
        account_to_vendor=account_to_vendor,
        current_account_id=current_account_id,
        region=region,
        owner_account=resource_owner,
        owner_label=_owner_label(resource_owner, account_aliases, org_accounts),
        actions=list(actions) if isinstance(actions, list) else [],
    )
    if grant is None:
        return None

    if is_public:
        grant["is_public"] = True
        grant["classification"] = "public"
        grant["principal_label"] = "Everyone (public)"

    if resource_type == "AWS::IAM::Role" and not grant["is_public"] and grant.get("principal_kind") == "aws_account":
        grant["missing_external_id"] = should_flag_missing_external_id(
            resource_type=resource_type,
            mechanism="access_analyzer",
            parsed={
                "kind": grant.get("principal_kind"),
                "is_public": grant.get("is_public"),
            },
            classification=grant.get("classification") or "unknown",
            resource=resource,
            condition=condition if isinstance(condition, dict) else {},
        )

    if grant.get("principal_kind") == "federated":
        raw_fed = ""
        if isinstance(principal, dict):
            raw_fed = str(principal.get("Federated") or next(iter(principal.values()), ""))
        gaps = oidc_condition_gaps(raw_fed, condition)
        grant["oidc_gaps"] = gaps
        grant["missing_oidc_subject"] = bool(gaps)

    grant.update(
        {
            "id": finding_id,
            "analyzer_type": analyzer_type,
            "analyzed_at": analyzed_at_s,
            "resource_owner": resource_owner,
            "external_principal": grant.get("principal_account_id") or "",
            "condition": condition if isinstance(condition, dict) else {},
        }
    )
    return grant


def display_aa_results(report_data: dict[str, Any], coverage: dict[str, Any] | None = None) -> None:
    """Print analyzer identity lines; grant tables come from display_grants."""
    analyzers = report_data.get("analyzers") or {}
    for region, analyzer in analyzers.items():
        created = analyzer.get("created_at") or ""
        extra = f", created {created}" if created else ""
        console.print(
            f"[dim]Analyzer in {region}: {analyzer['name']} "
            f"({analyzer['type']}{extra})[/dim]"
        )
    for note in (coverage or {}).get("analyzer_notes") or report_data.get("analyzer_notes") or []:
        console.print(f"[yellow]{note}[/yellow]")


# ---------------------------------------------------------------------------
# HTML report (iamtrail.com design system)
# ---------------------------------------------------------------------------

# Inline CSS reproducing the iamtrail.com design tokens (zinc dark theme, red
# accent, monospace headings, KPI cards, red-tinted section headers). Kept in
# one place so it can be shared between the legacy and AA report writers.
HTML_REPORT_CSS = """
:root {
  color-scheme: dark;
  --bg: #09090b;
  --bg-elev: #18181b;
  --bg-elev-2: #27272a;
  --border: #27272a;
  --border-strong: #3f3f46;
  --text: #fafafa;
  --text-muted: #a1a1aa;
  --text-dim: #71717a;
  --accent: #dc2626;
  --accent-bg: rgba(127, 29, 29, 0.30);
  --accent-border: rgba(127, 29, 29, 0.50);
  --accent-text: #f87171;
  --success: #34d399;
  --warn: #fbbf24;
  --danger: #f87171;
  --info: #60a5fa;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: var(--sans);
  font-size: 14px; line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent-text); text-decoration: none; }
a:hover { color: var(--accent); }
.container { max-width: 1280px; margin: 0 auto; padding: 0 24px; }
.nav {
  position: sticky; top: 0; z-index: 50;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}
.nav-inner {
  display: flex; justify-content: space-between; align-items: center;
  height: 56px;
}
.brand {
  font-family: var(--mono);
  font-weight: 700; font-size: 18px;
  color: var(--text); letter-spacing: -0.025em;
}
.brand .underscore { color: var(--accent); }
.nav-meta {
  font-family: var(--mono); font-size: 12px;
  color: var(--text-muted);
}
.hero {
  padding: 48px 0 24px;
  border-bottom: 1px solid var(--bg-elev);
}
.hero h1 {
  font-family: var(--mono);
  font-size: 42px; font-weight: 800;
  letter-spacing: -0.025em;
  margin: 0 0 16px;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  font-family: var(--mono);
  font-size: 10px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.15em;
  background: var(--bg-elev); color: var(--text-muted);
  border-radius: 4px;
}
.hero p { font-size: 18px; color: var(--text); margin: 0 0 8px; }
.hero p .accent { color: var(--accent-text); font-weight: 600; }
.hero .meta {
  font-size: 13px; color: var(--text-muted);
  font-family: var(--mono);
  margin-top: 12px;
}
.meta-row { display: flex; flex-wrap: wrap; gap: 8px 18px; }
.meta-row span strong { color: var(--text); font-weight: 600; }
.kpis {
  display: grid; gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  margin: 32px 0;
}
.kpi {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
}
.kpi-label {
  font-family: var(--mono);
  font-size: 11px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-muted);
}
.kpi-value {
  font-family: var(--mono);
  font-size: 28px; font-weight: 700;
  color: var(--text);
  margin-top: 8px; line-height: 1;
}
.kpi-sub { font-size: 11px; color: var(--text-dim); margin-top: 6px; }
.kpi.danger { border-color: var(--accent-border); }
.kpi.danger .kpi-value { color: var(--accent-text); }
.section {
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  margin: 24px 0;
}
.section-header {
  padding: 16px 20px;
  background: var(--accent-bg);
  border-bottom: 1px solid var(--accent-border);
}
.section-header.neutral {
  background: var(--bg-elev);
  border-bottom: 1px solid var(--border);
}
.section-title {
  font-family: var(--mono);
  font-size: 13px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.15em;
  color: var(--accent-text);
  margin: 0;
}
.section-header.neutral .section-title { color: var(--text-muted); }
.section-sub {
  font-size: 12px; color: var(--text-muted);
  margin-top: 4px;
}
.section-body { padding: 0; }
.section-body.empty {
  padding: 20px;
  color: var(--text-muted);
  font-style: italic;
}
table {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}
thead th {
  font-family: var(--mono);
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--text-muted);
  text-align: left;
  padding: 12px 20px;
  background: var(--bg-elev);
  border-bottom: 1px solid var(--border);
}
tbody td {
  padding: 12px 20px;
  border-bottom: 1px solid var(--bg-elev);
  vertical-align: top;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(39, 39, 42, 0.5); }
.mono { font-family: var(--mono); }
.muted { color: var(--text-muted); }
.dim { color: var(--text-dim); }
.pill {
  display: inline-block;
  font-family: var(--mono);
  font-size: 10px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.08em;
  padding: 2px 8px; border-radius: 4px;
  border: 1px solid var(--border-strong);
  color: var(--text-muted);
}
.pill.success { color: var(--success); border-color: rgba(52, 211, 153, 0.4); }
.pill.warn { color: var(--warn); border-color: rgba(251, 191, 36, 0.4); }
.pill.danger { color: var(--danger); border-color: rgba(248, 113, 113, 0.4); }
.pill.info { color: var(--info); border-color: rgba(96, 165, 250, 0.4); }
.pill.vendor { color: var(--accent-text); border-color: var(--accent-border); }
.callout {
  margin: 16px 0;
  padding: 16px 20px;
  background: var(--accent-bg);
  border: 1px solid var(--accent-border);
  border-radius: 8px;
  color: var(--text);
  font-size: 13px;
}
.callout strong { color: var(--accent-text); }
.callout.info {
  background: rgba(96, 165, 250, 0.10);
  border-color: rgba(96, 165, 250, 0.35);
}
.callout.info strong { color: var(--info); }
.tags { display: flex; flex-wrap: wrap; gap: 4px; }
.tag {
  font-family: var(--mono); font-size: 11px;
  padding: 2px 6px; border-radius: 3px;
  background: var(--bg-elev-2); color: var(--text-muted);
}
.resource-cell {
  font-family: var(--mono);
  word-break: break-all;
}
.resource-cell .arn { color: var(--text); font-weight: 500; }
.resource-cell .region { color: var(--text-dim); font-size: 11px; margin-top: 2px; }
.footer {
  padding: 32px 0 48px;
  color: var(--text-dim);
  font-size: 12px;
  text-align: center;
  border-top: 1px solid var(--bg-elev);
  margin-top: 32px;
}
.footer a { color: var(--text-muted); }
details.coverage {
  margin: 40px 0 8px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-elev);
}
details.coverage > summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 20px;
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text-muted);
}
details.coverage > summary::-webkit-details-marker { display: none; }
details.coverage > summary::after {
  content: "Show";
  float: right;
  font-weight: 500;
  letter-spacing: 0.08em;
  color: var(--text-dim);
}
details.coverage[open] > summary::after { content: "Hide"; }
details.coverage[open] > summary {
  border-bottom: 1px solid var(--border);
}
details.coverage .coverage-body { padding: 8px 20px 20px; }
details.coverage .section { margin: 16px 0 0; }
details.coverage .callout { margin: 16px 0 0; }
"""


def _h(value: Any) -> str:
    """Shortcut for HTML-escaping arbitrary values to plain strings."""
    if value is None:
        return ""
    return html.escape(str(value))


def _html_pill(label: str, kind: str = "") -> str:
    klass = "pill"
    if kind:
        klass += f" {kind}"
    return f'<span class="{klass}">{_h(label)}</span>'


def _html_classification_pill(finding: dict[str, Any]) -> str:
    classification = finding["classification"]
    if classification == "public":
        return _html_pill("public", "danger")
    if classification == "federated":
        return _html_pill(finding.get("principal_label") or "federated", "info")
    if classification == "trusted":
        name = finding.get("trusted", {}).get("name", "trusted") if finding.get("trusted") else "trusted"
        return _html_pill(f"trusted: {name}", "success")
    if classification == "vendor":
        vendor = finding.get("vendor") or {}
        name = vendor.get("name", "vendor")
        sources = vendor.get("source") or []
        first_source = sources[0] if isinstance(sources, list) and sources else None
        pill = _html_pill(f"vendor: {name}", "vendor")
        if first_source:
            return f'<a href="{_h(first_source)}" target="_blank" rel="noopener noreferrer">{pill}</a>'
        return pill
    if classification == "blocked_public":
        return _html_pill("blocked by BPA", "warn")
    return _html_pill("unknown", "warn")


def _html_principal_cell(finding: dict[str, Any]) -> str:
    if finding.get("is_public"):
        return '<span class="dim mono">Everyone (public)</span>'
    label = finding.get("principal_label") or ""
    if not label:
        return '<span class="dim">-</span>'
    return f'<span class="mono">{_h(label)}</span>'


def _html_resource_cell(finding: dict[str, Any]) -> str:
    arn = finding.get("resource", "")
    region = finding.get("region", "")
    label = grant_resource_label(finding)
    rtype = finding.get("resource_type") or ""
    type_line = " ".join(p for p in (rtype, region) if p)
    return (
        '<div class="resource-cell">'
        f'<div class="arn">{_h(label) or "-"}</div>'
        f'<div class="region">{_h(type_line)}</div>'
        f'<div class="region">{_h(arn)}</div>'
        "</div>"
    )


def _html_actions_cell(actions: list[str]) -> str:
    if not actions:
        return '<span class="dim">-</span>'
    visible = actions[:6]
    extra = len(actions) - len(visible)
    tags = "".join(f'<span class="tag">{_h(a)}</span>' for a in visible)
    if extra > 0:
        tags += f'<span class="tag">+{extra} more</span>'
    return f'<div class="tags">{tags}</div>'


def _render_kpi(label: str, value: Any, sub: str = "", danger: bool = False) -> str:
    klass = "kpi danger" if danger else "kpi"
    sub_html = f'<div class="kpi-sub">{_h(sub)}</div>' if sub else ""
    return (
        f'<div class="{klass}">'
        f'<div class="kpi-label">{_h(label)}</div>'
        f'<div class="kpi-value">{_h(value)}</div>'
        f"{sub_html}"
        "</div>"
    )


def _render_section(
    title: str,
    rows_html: str,
    columns: list[str],
    *,
    subtitle: str = "",
    empty_message: str = "",
    neutral: bool = False,
) -> str:
    header_class = "section-header neutral" if neutral else "section-header"
    sub_html = f'<div class="section-sub">{_h(subtitle)}</div>' if subtitle else ""
    if not rows_html:
        body = f'<div class="section-body empty">{_h(empty_message or "No findings.")}</div>'
    else:
        header_cells = "".join(f"<th>{_h(c)}</th>" for c in columns)
        body = (
            '<div class="section-body">'
            f'<table><thead><tr>{header_cells}</tr></thead><tbody>{rows_html}</tbody></table>'
            "</div>"
        )
    return (
        '<section class="section">'
        f'<div class="{header_class}">'
        f'<h2 class="section-title">{_h(title)}</h2>'
        f"{sub_html}"
        "</div>"
        f"{body}"
        "</section>"
    )


def _html_document(*, title: str, header_html: str, body_html: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_h(title)}</title>\n"
        f"<style>{HTML_REPORT_CSS}</style>\n"
        "</head>\n<body>\n"
        '<nav class="nav"><div class="container nav-inner">'
        '<a class="brand" href="#">Trustline<span class="underscore">_</span></a>'
        f"{header_html}"
        "</div></nav>\n"
        '<main class="container">\n'
        f"{body_html}\n"
        "</main>\n"
        '<footer class="footer container">'
        'Generated by <a href="https://github.com/zoph-io/aws-trustline" target="_blank" rel="noopener noreferrer">AWS Trustline</a>'
        ' &middot; design inspired by <a href="https://iamtrail.com" target="_blank" rel="noopener noreferrer">iamtrail.com</a>'
        " &middot; a service by <a href=\"https://zoph.io\" target=\"_blank\" rel=\"noopener noreferrer\">zoph.io</a>"
        "</footer>\n"
        "</body>\n</html>\n"
    )


def _render_coverage_html(coverage: dict[str, Any]) -> str:
    scanned_rows = "".join(
        f"<tr><td>{_h(item['surface'])}</td><td class=\"muted\">{_h(item['detail'])}</td></tr>"
        for item in coverage.get("scanned") or []
    )
    skipped_rows = "".join(
        f"<tr><td>{_h(item['surface'])}</td><td class=\"muted\">{_h(item['detail'])}</td></tr>"
        for item in coverage.get("not_scanned") or []
    )
    notes = "".join(
        f"<li>{_h(note)}</li>" for note in coverage.get("analyzer_notes") or []
    )
    notes_html = f"<ul>{notes}</ul>" if notes else ""
    n_scanned = len(coverage.get("scanned") or [])
    n_skip = len(coverage.get("not_scanned") or [])
    scanned_table = _render_section(
        "Scanned",
        scanned_rows,
        ["Surface", "Detail"],
        empty_message="Nothing was scanned.",
        neutral=True,
    )
    aa_blurb = ""
    if coverage.get("backend") == "access_analyzer":
        aa_blurb = (
            " Analyzer status ACTIVE is not scan-complete; first scans can take "
            "~20 minutes."
        )
    return (
        '<details class="coverage">'
        f"<summary>Coverage — {n_scanned} scanned, {n_skip} not scanned</summary>"
        '<div class="coverage-body">'
        '<div class="callout info"><strong>The inventory only covers scanned surfaces.</strong>'
        f"{aa_blurb}"
        f"{notes_html}</div>"
        + scanned_table
        + _render_section(
            "Not scanned",
            skipped_rows,
            ["Surface", "Why"],
            subtitle="Out of scope, skipped, or collector errors",
        )
        + "</div></details>"
    )


def _grant_table_rows(items: list[dict[str, Any]], *, show_owner: bool) -> str:
    return "".join(
        "<tr>"
        f"<td>{_html_resource_cell(g)}</td>"
        + (f'<td><span class="mono">{_h(g.get("owner_label") or "-")}</span></td>' if show_owner else "")
        + f"<td>{_html_principal_cell(g)}</td>"
        f"<td>{_html_classification_pill(g)}</td>"
        f"<td class=\"muted\">{_h(MECHANISM_LABELS.get(g.get('mechanism') or '', g.get('mechanism') or '-'))}</td>"
        f"<td>{_html_actions_cell(g.get('actions') or [])}</td>"
        "</tr>"
        for g in items
    )


def generate_html_report(
    grants: list[dict[str, Any]],
    coverage: dict[str, Any],
    *,
    account_aliases: dict[str, str],
    scope: str = "account",
    output_dir: str = ".",
    org_error: str | None = None,
    badge: str = "Policy scanner",
) -> str:
    """Write HTML: inventory by principal, leftover flags, coverage appendix."""
    totals = totals_from_grants(grants)
    parties = parties_from_grants(grants)
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    if scope == "organization":
        identity_slug = "org"
        owner_count = len({g.get("owner_account") for g in grants if g.get("owner_account")})
        identity_label = f"AWS Organization ({owner_count} owner accounts)"
    else:
        identity_slug = current_account_id
        identity_label = f"{current_account_id} ({current_account_alias})"

    report_file = _report_filename(output_dir, identity_slug, "html")
    show_owner = scope == "organization"

    header_html = (
        f'<div class="nav-meta">{_h(identity_label)}'
        f' &middot; {_h(scope)} scope</div>'
    )
    hero_html = (
        '<section class="hero"><div>'
        '<h1>Trustline<span style="color:var(--accent)">_</span>'
        f'<span class="badge">{_h(badge)}</span></h1>'
        '<p>Current external access on this account. 12-digit account IDs are '
        'looked up in the '
        '<a href="https://github.com/fwdcloudsec/known_aws_accounts" target="_blank" rel="noopener noreferrer">fwd:cloudsec</a> '
        'dataset. Unresolved IDs were not in that list, your YAML, or Organizations.</p>'
        '<div class="meta meta-row">'
        f"<span><strong>Account/Org:</strong> {_h(identity_label)}</span>"
        f"<span><strong>Parties:</strong> {len(parties)}</span>"
        f"<span><strong>Grants:</strong> {totals['findings']}</span>"
        f"<span><strong>Generated:</strong> {_h(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</span>"
        "</div></div></section>"
    )
    kpis_html = (
        '<div class="kpis">'
        + _render_kpi("External parties", len(parties), "Grouped by account ID or issuer")
        + _render_kpi("Not in dataset", totals["unknown"], "Looked up, no name", danger=totals["unknown"] > 0)
        + _render_kpi("Known vendors", totals["vendors"], "fwd:cloudsec + AWS aliases")
        + _render_kpi("Trusted", totals["trusted"], "Org + YAML + CloudFront OAI")
        + _render_kpi("Federated", totals["federated"], "OIDC / SAML / Cognito")
        + _render_kpi("Public", totals["public"], "Currently public", danger=totals["public"] > 0)
        + _render_kpi("Missing ExternalId", totals["missing_external_id"], "Confused deputy", danger=totals["missing_external_id"] > 0)
        + _render_kpi("OIDC gaps", totals["missing_oidc_subject"], "Missing sub/aud", danger=totals["missing_oidc_subject"] > 0)
        + "</div>"
    )

    columns = ["Resource"]
    if show_owner:
        columns.append("Owner")
    columns.extend(["Principal", "Classification", "Mechanism", "Actions"])

    def section(title: str, items: list[dict[str, Any]], empty: str, *, subtitle: str = "", neutral: bool = False) -> str:
        if not items:
            return ""
        return _render_section(
            title,
            _grant_table_rows(items, show_owner=show_owner),
            columns,
            subtitle=subtitle or f"{len(items)} grant(s)",
            empty_message=empty,
            neutral=neutral,
        )

    party_rows = "".join(
        "<tr>"
        f"<td>{_h(party['name'])}</td>"
        f"<td class=\"muted\">{_h(party['name_source_label'])}</td>"
        f"<td>{_h(party['classification'])}</td>"
        f"<td>{party['grant_count']}</td>"
        f"<td class=\"muted\">{_h(', '.join(party['mechanisms']))}</td>"
        f"<td class=\"muted\">{_h(_party_resource_summary(party))}</td>"
        "</tr>"
        for party in parties
    )
    if parties:
        inventory_html = _render_section(
            "External access by principal",
            party_rows,
            ["Principal", "Name source", "Classification", "Grants", "Mechanisms", "Resources"],
            subtitle=f"{len(parties)} external part{'y' if len(parties) == 1 else 'ies'}",
            empty_message="No current external access in scanned surfaces.",
            neutral=True,
        )
    else:
        inventory_html = (
            '<div class="callout info"><strong>No current external access</strong> '
            "in scanned surfaces.</div>"
        )

    parts: list[str] = []
    if org_error:
        parts.append(
            '<div class="callout"><strong>AWS Organizations:</strong> '
            f"{_h(org_error)}</div>"
        )
    parts.append(inventory_html)
    parts.append(
        section(
            "OIDC trusts missing sub/aud",
            [g for g in grants if g.get("missing_oidc_subject")],
            "No GitHub/GitLab trusts missing subject or audience conditions.",
        )
    )
    parts.append(
        section(
            "IAM roles missing ExternalId",
            [g for g in grants if g.get("missing_external_id")],
            "No cross-account roles missing sts:ExternalId.",
        )
    )
    parts.append(
        section(
            "Never-expiring service-specific credentials",
            [g for g in grants if g.get("never_expires")],
            "No active never-expiring service-specific credentials.",
        )
    )
    parts.append(
        section(
            "Policy allows everyone; Block Public Access denies it",
            [g for g in grants if g.get("blocked_by_bpa")],
            "No BPA-blocked public policies.",
            subtitle="Allow * is in the policy but GetBucketPolicyStatus is not public.",
            neutral=True,
        )
    )

    parts.append(_render_coverage_html(coverage))

    body_html = hero_html + kpis_html + "\n".join(part for part in parts if part)
    with open(report_file, "w") as fh:
        fh.write(
            _html_document(
                title=f"Trustline Report - {identity_label}",
                header_html=header_html,
                body_html=body_html,
            )
        )
    return report_file


def generate_html_report_aa(
    report_data: dict[str, Any],
    *,
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    scope: str,
    output_dir: str = ".",
) -> str:
    """Lambda-compatible wrapper around the unified HTML writer."""
    grants = list(report_data.get("grants") or [])
    coverage = report_data.get("coverage") or build_coverage(
        backend="access_analyzer",
        scanned=[{"surface": "IAM Access Analyzer", "detail": "external-access findings"}],
        analyzer_notes=report_data.get("analyzer_notes") or [],
    )
    return generate_html_report(
        grants,
        coverage,
        account_aliases=account_aliases,
        scope=scope,
        output_dir=output_dir,
        badge="Access Analyzer",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustline",
        description=(
            "AWS Trustline - Map current external access in your AWS account "
            "and name the vendor when the account ID is known."
        ),
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("-p", "--profile", help="AWS profile name to use for authentication")
    parser.add_argument("-r", "--region", help="AWS region (overrides profile/env default)")
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT_DIR,
        help=(
            f"Output directory for report files (default: {DEFAULT_OUTPUT_DIR}/). "
            "Each run writes a timestamped file. Existing reports are never overwritten."
        ),
    )
    parser.add_argument(
        "-t", "--trusted-accounts",
        default=DEFAULT_TRUSTED_ACCOUNTS_FILE,
        help=f"Path to trusted accounts YAML file (default: {DEFAULT_TRUSTED_ACCOUNTS_FILE})",
    )
    parser.add_argument("--skip-iam", action="store_true", help="Skip IAM role trust policies")
    parser.add_argument("--skip-s3", action="store_true", help="Skip S3 bucket policies")
    parser.add_argument("--skip-ram", action="store_true", help="Skip RAM resource shares")
    parser.add_argument("--skip-ami", action="store_true", help="Skip AMI launch permissions")
    parser.add_argument("--skip-ssm", action="store_true", help="Skip SSM document shares")
    parser.add_argument(
        "--skip-credentials",
        action="store_true",
        help="Skip IAM service-specific credentials / long-lived API keys",
    )
    backend_group = parser.add_mutually_exclusive_group()
    backend_group.add_argument(
        "--use-access-analyzer",
        action="store_true",
        help=(
            "Require IAM Access Analyzer (fail if none exists). Default is to "
            "use analyzers when found and walk IAM/S3 policies otherwise. "
            "RAM, AMI, SSM, and credentials still run unless skipped."
        ),
    )
    backend_group.add_argument(
        "--policy-scanner",
        action="store_true",
        help=(
            "Walk IAM role trusts and S3 bucket policies even if Access Analyzer "
            "exists. Public S3 rows are checked with GetBucketPolicyStatus."
        ),
    )
    parser.add_argument(
        "--wait-for-analyzer",
        action="store_true",
        help=(
            "Poll Access Analyzer until ACTIVE finding counts stabilize. "
            "Applies when analyzers are used (default hybrid or --use-access-analyzer). "
            "ACTIVE is not scan-complete; first scans can take ~20 minutes."
        ),
    )
    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=DEFAULT_WAIT_TIMEOUT,
        help=f"Seconds to wait with --wait-for-analyzer (default: {DEFAULT_WAIT_TIMEOUT})",
    )
    parser.add_argument(
        "--scope",
        choices=["auto", "account", "organization"],
        default="auto",
        help=(
            "Access Analyzer scope: 'account' (this account), 'organization' "
            "(run from the org management or AA delegated-admin account), or "
            "'auto' (default: prefer ACCOUNT analyzers so the inventory is this "
            "account; ORGANIZATION only if no ACCOUNT analyzer exists)"
        ),
    )
    region_group = parser.add_mutually_exclusive_group()
    region_group.add_argument(
        "--regions",
        help="Comma-separated regions for regional collectors (RAM, AMI, SSM, AA)",
    )
    region_group.add_argument(
        "--all-regions",
        action="store_true",
        help="Enumerate every enabled region via ec2:DescribeRegions",
    )
    parser.add_argument(
        "--format",
        choices=["html", "md", "both"],
        default=None,
        help="Report format(s). Default: html when Access Analyzer is used, md for the policy scanner.",
    )
    parser.add_argument("--verbose", action="store_true", help="Show full error tracebacks")
    return parser


def _resolve_format(args: argparse.Namespace, using_access_analyzer: bool) -> str:
    if args.format:
        return args.format
    return "html" if using_access_analyzer else "md"


def _try_resolve_regions(session: boto3.Session, args: argparse.Namespace) -> list[str]:
    try:
        return resolve_regions(session, args)
    except (ValueError, RuntimeError) as e:
        console.print(f"[yellow]Warning: could not resolve regions: {e}[/yellow]")
        return []


def _write_reports(
    grants: list[dict[str, Any]],
    coverage: dict[str, Any],
    *,
    args: argparse.Namespace,
    account_aliases: dict[str, str],
    output_format: str,
    org_error: str | None,
    scope: str,
    badge: str,
) -> None:
    os.makedirs(args.output, exist_ok=True)
    if output_format in ("md", "both"):
        md_path = generate_markdown_report(
            grants,
            coverage,
            account_aliases=account_aliases,
            org_error=org_error,
            output_dir=args.output,
            identity_slug="org" if scope == "organization" else None,
        )
        console.print(f"\n[bold green]Markdown report: {md_path}[/bold green]")
    if output_format in ("html", "both"):
        html_path = generate_html_report(
            grants,
            coverage,
            account_aliases=account_aliases,
            scope=scope,
            output_dir=args.output,
            org_error=org_error,
            badge=badge,
        )
        console.print(f"[bold green]HTML report: {html_path}[/bold green]")


def _run_access_analyzer_backend(
    session: boto3.Session,
    args: argparse.Namespace,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    org_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    output_format: str,
    our_organization_id: str | None,
    org_error: str | None,
    analyzers: dict[str, dict[str, str]] | None = None,
) -> int:
    try:
        regions = resolve_regions(session, args)
    except (ValueError, RuntimeError) as e:
        console.print(f"[bold red]Error resolving regions: {e}[/bold red]")
        return 1

    if analyzers is None:
        console.print(
            f"[bold]Discovering external analyzers in {len(regions)} region(s) "
            f"(scope: {args.scope})...[/bold]"
        )
        analyzers = find_external_analyzers(session, regions, args.scope)

    missing = [r for r in regions if r not in analyzers]
    if missing:
        console.print(
            f"[yellow]No matching external analyzer in: {', '.join(missing)}[/yellow]"
        )

    if not analyzers:
        scope_hint = "ORGANIZATION" if args.scope == "organization" else "ACCOUNT"
        console.print(
            "[bold red]No external Access Analyzer found in any requested "
            "region.[/bold red]"
        )
        console.print("[yellow]Create a free external-access analyzer with:[/yellow]")
        console.print(
            f"  [cyan]aws accessanalyzer create-analyzer "
            f"--analyzer-name trustline --type {scope_hint}[/cyan]"
        )
        return 1

    for region, analyzer in analyzers.items():
        console.print(
            f"[green]Found {analyzer['type']} analyzer in {region}: "
            f"{analyzer['name']}[/green]"
        )

    wait_notes: list[str] = []
    if args.wait_for_analyzer:
        wait_notes = wait_for_analyzer_findings(
            session, analyzers, timeout=max(1, args.wait_timeout)
        )

    current_account_id = next(iter(account_aliases), "")
    restrict_to_owner = (
        None if args.scope == "organization" else current_account_id or None
    )
    report_data = collect_access_analyzer_findings(
        session=session,
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
        analyzers=analyzers,
        our_organization_id=our_organization_id,
        restrict_to_owner=restrict_to_owner,
    )
    report_data["analyzer_notes"] = (
        wait_notes + list(report_data.get("analyzer_notes") or [])
    )

    kwargs = grant_collect_context(
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        current_account_id=current_account_id,
        our_organization_id=our_organization_id,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
    )
    extra, scanned, skipped = collect_optional_scanners(session, args, regions, kwargs)
    grants = list(report_data.get("grants") or []) + extra
    report_data["grants"] = grants
    report_data["totals"] = totals_from_grants(grants)
    report_data["totals"]["regions"] = len(analyzers)
    report_data["totals"]["owner_accounts"] = len(report_data.get("owner_accounts") or [])

    coverage = build_coverage(
        backend="access_analyzer",
        scanned=(
            [{"surface": "IAM Access Analyzer external findings", "detail": ", ".join(analyzers)}]
            + scanned
        ),
        skipped=skipped,
        regions=regions,
        all_regions=bool(args.all_regions),
        analyzer_notes=report_data["analyzer_notes"],
    )
    report_data["coverage"] = coverage

    display_aa_results(report_data, coverage)
    display_grants(grants, coverage, account_aliases)

    effective_scope = report_scope_label(args.scope)
    _write_reports(
        grants,
        coverage,
        args=args,
        account_aliases=account_aliases,
        output_format=output_format,
        org_error=org_error,
        scope=effective_scope,
        badge="Access Analyzer",
    )
    return 0


def _run_policy_scanner(
    session: boto3.Session,
    args: argparse.Namespace,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    org_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_error: str | None,
    output_format: str,
    our_organization_id: str | None,
) -> int:
    current_account_id = next(iter(account_aliases), "")
    kwargs = grant_collect_context(
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        current_account_id=current_account_id,
        our_organization_id=our_organization_id,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
    )
    regions = _try_resolve_regions(session, args)
    grants: list[dict[str, Any]] = []
    scanned: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    if args.skip_iam:
        skipped.append({"surface": "IAM role trust policies", "detail": "--skip-iam"})
    else:
        grants.extend(collect_iam_role_grants(session, **kwargs))
        scanned.append({"surface": "IAM role trust policies", "detail": "this account"})

    if args.skip_s3:
        skipped.append({"surface": "S3 bucket policies", "detail": "--skip-s3"})
    else:
        grants.extend(collect_s3_bucket_grants(session, **kwargs))
        scanned.append({"surface": "S3 bucket policies", "detail": "this account"})

    extra, extra_scanned, extra_skipped = collect_optional_scanners(
        session, args, regions, kwargs
    )
    grants.extend(extra)
    scanned.extend(extra_scanned)
    skipped.extend(extra_skipped)

    coverage = build_coverage(
        backend="policy_scanner",
        scanned=scanned,
        skipped=skipped,
        regions=regions,
        all_regions=bool(args.all_regions),
    )
    display_grants(grants, coverage, account_aliases)
    _write_reports(
        grants,
        coverage,
        args=args,
        account_aliases=account_aliases,
        output_format=output_format,
        org_error=org_error,
        scope="account",
        badge="Policy scanner",
    )
    return 0


def _all_collectors_skipped(args: argparse.Namespace) -> bool:
    extras = (
        args.skip_ram
        and args.skip_ami
        and args.skip_ssm
        and args.skip_credentials
    )
    if args.use_access_analyzer:
        return extras
    if getattr(args, "policy_scanner", False):
        return extras and args.skip_iam and args.skip_s3
    return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.use_access_analyzer and (args.skip_iam or args.skip_s3):
        console.print(
            "[bold red]Error: --use-access-analyzer is mutually exclusive with "
            "--skip-iam / --skip-s3 (AA replaces those collectors).[/bold red]"
        )
        return 1
    if args.wait_for_analyzer and getattr(args, "policy_scanner", False):
        console.print(
            "[bold red]Error: --wait-for-analyzer cannot be combined with "
            "--policy-scanner.[/bold red]"
        )
        return 1
    if _all_collectors_skipped(args):
        console.print("[bold red]Error: every collector is skipped.[/bold red]")
        return 1

    session_kwargs: dict[str, str] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region
    session = boto3.Session(**session_kwargs)

    try:
        console.print(
            Panel(
                "[bold cyan]AWS Trustline[/bold cyan]\n"
                "Map current external access and name the vendor when the account is known.",
                title="AWS Trustline",
                box=box.ROUNDED,
            )
        )

        console.print("[bold]Fetching reference data of known AWS accounts...[/bold]")
        account_to_vendor = fetch_reference_data()
        console.print(
            f"[green]Found {len(account_to_vendor)} known AWS accounts in the reference data[/green]"
        )

        console.print("[bold]Loading trusted AWS accounts...[/bold]")
        trusted_accounts, org_error = fetch_trusted_accounts(session, args.trusted_accounts)
        org_accounts = {
            acct_id: meta
            for acct_id, meta in trusted_accounts.items()
            if meta.get("source") == "aws_org"
        }
        our_organization_id = fetch_organization_id(session)
        account_aliases = get_account_aliases(session)

        if getattr(args, "policy_scanner", False):
            output_format = _resolve_format(args, False)
            console.print(
                f"[dim]Backend:[/dim] Policy scanner    [dim]Output:[/dim] {output_format}"
            )
            return _run_policy_scanner(
                session=session,
                args=args,
                account_to_vendor=account_to_vendor,
                trusted_accounts=trusted_accounts,
                org_accounts=org_accounts,
                account_aliases=account_aliases,
                org_error=org_error,
                output_format=output_format,
                our_organization_id=our_organization_id,
            )

        regions = _try_resolve_regions(session, args)
        analyzers: dict[str, dict[str, str]] = {}
        if regions:
            console.print(
                f"[bold]Looking for external analyzers in {len(regions)} region(s) "
                f"(scope: {args.scope})...[/bold]"
            )
            analyzers = find_external_analyzers(session, regions, args.scope)

        if analyzers:
            output_format = _resolve_format(args, True)
            if not args.use_access_analyzer:
                console.print(
                    "[green]Access Analyzer found — using it for IAM/S3-class resources "
                    "(effective access). Pass --policy-scanner to walk policies instead.[/green]"
                )
            console.print(
                f"[dim]Backend:[/dim] Access Analyzer    [dim]Output:[/dim] {output_format}"
            )
            return _run_access_analyzer_backend(
                session=session,
                args=args,
                account_to_vendor=account_to_vendor,
                trusted_accounts=trusted_accounts,
                org_accounts=org_accounts,
                account_aliases=account_aliases,
                output_format=output_format,
                our_organization_id=our_organization_id,
                org_error=org_error,
                analyzers=analyzers,
            )

        if args.use_access_analyzer:
            return _run_access_analyzer_backend(
                session=session,
                args=args,
                account_to_vendor=account_to_vendor,
                trusted_accounts=trusted_accounts,
                org_accounts=org_accounts,
                account_aliases=account_aliases,
                output_format=_resolve_format(args, True),
                our_organization_id=our_organization_id,
                org_error=org_error,
                analyzers={},
            )

        if args.wait_for_analyzer:
            console.print(
                "[yellow]--wait-for-analyzer ignored: no analyzer found; "
                "walking IAM/S3 policies.[/yellow]"
            )
        output_format = _resolve_format(args, False)
        console.print(
            "[yellow]No external Access Analyzer in requested regions; "
            "walking IAM/S3 policies.[/yellow]"
        )
        console.print(
            f"[dim]Backend:[/dim] Policy scanner    [dim]Output:[/dim] {output_format}"
        )
        return _run_policy_scanner(
            session=session,
            args=args,
            account_to_vendor=account_to_vendor,
            trusted_accounts=trusted_accounts,
            org_accounts=org_accounts,
            account_aliases=account_aliases,
            org_error=org_error,
            output_format=output_format,
            our_organization_id=our_organization_id,
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()
        return 1


if __name__ == "__main__":
    sys.exit(main())

