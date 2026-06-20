#!/usr/bin/env python3
"""
AWS Trustline - Map and audit third-party trust relationships in your AWS account.

Analyzes IAM Role trust policies and S3 bucket policies to identify third-party
vendors with access to your resources. Compares AWS account IDs found in these
policies against a reference list of known AWS accounts from fwd:cloudsec to
identify the vendors behind these accounts.

Usage:
    python trustline.py
    python trustline.py --profile my-profile --region us-east-1
    python trustline.py --skip-s3 --output /tmp/reports
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import boto3
import requests
import yaml
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

__version__ = "0.2.0"

REFERENCE_DATA_URL = (
    "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
)
DEFAULT_TRUSTED_ACCOUNTS_FILE = "trusted_accounts.yaml"
DEFAULT_OUTPUT_DIR = "reports"
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

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

# Human-readable labels for the AWS resource types that IAM Access Analyzer
# reports for external access. Keys match the `resourceType` field returned by
# `accessanalyzer:ListFindings`.
AA_RESOURCE_TYPE_LABELS: dict[str, str] = {
    "AWS::S3::Bucket": "S3 Buckets",
    "AWS::S3Express::DirectoryBucket": "S3 Directory Buckets",
    "AWS::IAM::Role": "IAM Roles",
    "AWS::IAM::User": "IAM Users",
    "AWS::KMS::Key": "KMS Keys",
    "AWS::Lambda::Function": "Lambda Functions",
    "AWS::Lambda::LayerVersion": "Lambda Layers",
    "AWS::SQS::Queue": "SQS Queues",
    "AWS::SNS::Topic": "SNS Topics",
    "AWS::SecretsManager::Secret": "Secrets Manager Secrets",
    "AWS::EFS::FileSystem": "EFS File Systems",
    "AWS::EC2::Snapshot": "EBS Snapshots",
    "AWS::ECR::Repository": "ECR Repositories",
    "AWS::RDS::DBSnapshot": "RDS DB Snapshots",
    "AWS::RDS::DBClusterSnapshot": "RDS Cluster Snapshots",
    "AWS::DynamoDB::Table": "DynamoDB Tables",
    "AWS::DynamoDB::Stream": "DynamoDB Streams",
}

console = Console()


def fetch_reference_data() -> dict[str, dict[str, Any]]:
    """Fetch the reference data of known AWS accounts from fwd:cloudsec on GitHub."""
    try:
        response = requests.get(REFERENCE_DATA_URL, timeout=15)
        response.raise_for_status()

        vendors_data = yaml.safe_load(response.text)

        account_to_vendor: dict[str, dict[str, Any]] = {}
        for vendor in vendors_data:
            for account_id in vendor.get("accounts", []):
                account_to_vendor[account_id] = {
                    "name": vendor.get("name", "Unknown"),
                    "type": vendor.get("type", "third-party"),
                    "source": vendor.get("source", []),
                }

        return account_to_vendor

    except Exception as e:
        console.print(f"[bold red]Error fetching reference data: {e}[/bold red]")
        return {}


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
            for account_id in entity.get("accounts", []):
                if account_id not in trusted_accounts:
                    trusted_accounts[account_id] = {
                        "name": entity.get("name", "Internal"),
                        "type": "trusted",
                        "description": entity.get("description", ""),
                        "source": "yaml_file",
                    }
                    yaml_count += 1

        console.print(
            f"[green]Loaded {yaml_count} additional trusted AWS accounts from YAML file[/green]"
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


def _extract_account_id_from_value(value: str) -> str | None:
    """Extract a 12-digit AWS account ID from an ARN or raw string."""
    if "arn:aws" in value:
        parts = value.split(":")
        if len(parts) >= 5 and ACCOUNT_ID_PATTERN.match(parts[4]):
            return parts[4]
    elif ACCOUNT_ID_PATTERN.match(value):
        return value
    return None


def extract_account_ids_from_policy(policy_document: dict[str, Any]) -> list[str]:
    """Extract unique AWS account IDs from a policy document."""
    account_ids: set[str] = set()

    def search_for_accounts(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "AWS":
                    principals = value if isinstance(value, list) else [value]
                    for item in principals:
                        if isinstance(item, str):
                            acct = _extract_account_id_from_value(item)
                            if acct:
                                account_ids.add(acct)
                else:
                    search_for_accounts(value)
        elif isinstance(node, list):
            for item in node:
                search_for_accounts(item)

    search_for_accounts(policy_document)
    return list(account_ids)


def check_external_id_condition(policy_document: dict[str, Any]) -> bool:
    """
    Check if ALL cross-account Allow statements in a trust policy have an
    ExternalId condition to prevent the confused deputy problem.

    Returns True only if every cross-account statement includes an ExternalId
    condition. Returns False if any cross-account statement is missing one, or
    if no cross-account statements are found.
    """
    if not policy_document or "Statement" not in policy_document:
        return False

    statements = policy_document["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    found_cross_account = False

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if not isinstance(principal, dict):
            continue

        aws_principal = principal.get("AWS", "")
        if not aws_principal:
            continue

        found_cross_account = True

        condition = statement.get("Condition", {})
        if not condition:
            return False

        has_external_id = False
        for condition_type, condition_values in condition.items():
            if condition_type in ("StringEquals", "StringLike", "ArnLike"):
                if "sts:ExternalId" in condition_values:
                    has_external_id = True
                    break

        if not has_external_id:
            return False

    return found_cross_account


def check_iam_role_trust_policies(
    session: boto3.Session,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
) -> tuple[dict, dict, dict, dict]:
    """Check IAM Role trust policies for external access."""
    console.print("[bold blue]Checking IAM role trust policies...[/bold blue]")

    iam_client = session.client("iam")
    known_vendors: dict[str, list[str]] = {}
    unknown_accounts: dict[str, list[str]] = {}
    trusted_entities: dict[str, dict[str, Any]] = {}
    vulnerable_roles: dict[str, dict[str, Any]] = {}

    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                trust_policy = role.get("AssumeRolePolicyDocument", {})
                account_ids = extract_account_ids_from_policy(trust_policy)

                for account_id in account_ids:
                    if account_id == "":
                        continue

                    if account_id in trusted_accounts:
                        trusted_name = trusted_accounts[account_id]["name"]
                        source = trusted_accounts[account_id]["source"]
                        if trusted_name not in trusted_entities:
                            trusted_entities[trusted_name] = {"roles": [], "source": source}
                        trusted_entities[trusted_name]["roles"].append(role_name)

                        if not check_external_id_condition(trust_policy):
                            if trusted_name not in vulnerable_roles:
                                vulnerable_roles[trusted_name] = {"roles": [], "source": source}
                            vulnerable_roles[trusted_name]["roles"].append(role_name)

                    elif account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(role_name)

                        if not check_external_id_condition(trust_policy):
                            if vendor_name not in vulnerable_roles:
                                vulnerable_roles[vendor_name] = {"roles": [], "source": "vendor"}
                            vulnerable_roles[vendor_name]["roles"].append(role_name)

                    else:
                        display_id = account_id
                        if account_id in account_aliases:
                            display_id = f"{account_id} ({account_aliases[account_id]})"

                        if display_id not in unknown_accounts:
                            unknown_accounts[display_id] = []
                        unknown_accounts[display_id].append(role_name)

                        if not check_external_id_condition(trust_policy):
                            if display_id not in vulnerable_roles:
                                vulnerable_roles[display_id] = {"roles": [], "source": "unknown"}
                            vulnerable_roles[display_id]["roles"].append(role_name)

        return known_vendors, unknown_accounts, trusted_entities, vulnerable_roles

    except Exception as e:
        console.print(
            f"[bold red]Error checking IAM role trust policies: {e}[/bold red]"
        )
        return {}, {}, {}, {}


def check_s3_bucket_policies(
    session: boto3.Session,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
) -> tuple[dict, dict, dict]:
    """Check S3 bucket policies for external access."""
    console.print("[bold blue]Checking S3 bucket policies...[/bold blue]")

    s3_client = session.client("s3")
    known_vendors: dict[str, list[str]] = {}
    unknown_accounts: dict[str, list[str]] = {}
    trusted_entities: dict[str, dict[str, Any]] = {}

    try:
        response = s3_client.list_buckets()
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]

            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_document = json.loads(policy_response["Policy"])
                account_ids = extract_account_ids_from_policy(policy_document)

                for account_id in account_ids:
                    if account_id in trusted_accounts:
                        trusted_name = trusted_accounts[account_id]["name"]
                        source = trusted_accounts[account_id]["source"]
                        if trusted_name not in trusted_entities:
                            trusted_entities[trusted_name] = {"buckets": [], "source": source}
                        trusted_entities[trusted_name]["buckets"].append(bucket_name)

                    elif account_id in account_to_vendor:
                        vendor_name = account_to_vendor[account_id]["name"]
                        if vendor_name not in known_vendors:
                            known_vendors[vendor_name] = []
                        known_vendors[vendor_name].append(bucket_name)

                    else:
                        display_id = account_id
                        if account_id in account_aliases:
                            display_id = f"{account_id} ({account_aliases[account_id]})"
                        if display_id not in unknown_accounts:
                            unknown_accounts[display_id] = []
                        unknown_accounts[display_id].append(bucket_name)

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
                console.print(
                    f"[yellow]Warning: Could not check policy for bucket {bucket_name}: "
                    f"{e.response['Error']['Message']}[/yellow]"
                )

        return known_vendors, unknown_accounts, trusted_entities

    except Exception as e:
        console.print(
            f"[bold red]Error checking S3 bucket policies: {e}[/bold red]"
        )
        return {}, {}, {}


def generate_report(
    iam_known_vendors: dict[str, list[str]],
    iam_unknown_accounts: dict[str, list[str]],
    iam_trusted_entities: dict[str, dict[str, Any]],
    iam_vulnerable_roles: dict[str, dict[str, Any]],
    s3_known_vendors: dict[str, list[str]],
    s3_unknown_accounts: dict[str, list[str]],
    s3_trusted_entities: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    output_dir: str = ".",
    org_error: str | None = None,
) -> str:
    """Generate a markdown report with the findings."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    report_file = os.path.join(
        output_dir, f"trustline_report_{current_account_id}_{timestamp}.md"
    )

    with open(report_file, "w") as f:
        f.write("# AWS Trustline - Access Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Account: {current_account_id} ({current_account_alias})\n\n")

        if org_error:
            f.write("## AWS Organizations Access\n\n")
            f.write(f"Could not access AWS Organizations API: {org_error}\n")
            f.write(
                "\nThis means the report may be missing trusted accounts from your AWS Organization.\n"
            )
            f.write(
                "To fix this, ensure the IAM identity running Trustline has the `organizations:ListAccounts` permission.\n\n"
            )

        f.write("# IAM Roles Analysis\n\n")

        f.write("## Trusted Entities with IAM Role Access\n\n")
        if iam_trusted_entities:
            f.write("| Entity | Source | IAM Roles |\n")
            f.write("|--------|--------|----------|\n")
            for entity, data in iam_trusted_entities.items():
                f.write(
                    f"| {entity} | {data['source']} | {', '.join(data['roles'])} |\n"
                )
        else:
            f.write("No trusted entities found in IAM role trust policies.\n")
        f.write("\n")

        f.write("## Known Vendors with IAM Role Access\n\n")
        if iam_known_vendors:
            f.write("| Vendor | IAM Roles |\n")
            f.write("|--------|----------|\n")
            for vendor, roles in iam_known_vendors.items():
                f.write(f"| {vendor} | {', '.join(roles)} |\n")
        else:
            f.write("No known vendors found in IAM role trust policies.\n")
        f.write("\n")

        f.write("## Unknown AWS Accounts with IAM Role Access\n\n")
        if iam_unknown_accounts:
            f.write("| AWS Account ID | Account Name | IAM Roles |\n")
            f.write("|---------------|------------|----------|\n")
            for account_id, roles in iam_unknown_accounts.items():
                account_name = account_aliases.get(account_id, "Unknown")
                f.write(f"| {account_id} | {account_name} | {', '.join(roles)} |\n")
        else:
            f.write("No unknown AWS accounts found in IAM role trust policies.\n")
        f.write("\n")

        f.write("## IAM Roles Missing ExternalId Condition\n\n")
        f.write(
            "These roles are vulnerable to the [confused deputy problem]"
            "(https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).\n\n"
        )
        if iam_vulnerable_roles:
            f.write("| Entity | Source | Vulnerable IAM Roles |\n")
            f.write("|--------|--------|--------------------|\n")
            for entity, data in iam_vulnerable_roles.items():
                f.write(
                    f"| {entity} | {data['source']} | {', '.join(data['roles'])} |\n"
                )
        else:
            f.write("No vulnerable IAM roles found.\n")
        f.write("\n")

        f.write("# S3 Bucket Policies Analysis\n\n")

        f.write("## Trusted Entities with S3 Bucket Access\n\n")
        if s3_trusted_entities:
            f.write("| Entity | Source | S3 Buckets |\n")
            f.write("|--------|--------|----------|\n")
            for entity, data in s3_trusted_entities.items():
                f.write(
                    f"| {entity} | {data['source']} | {', '.join(data['buckets'])} |\n"
                )
        else:
            f.write("No trusted entities found in S3 bucket policies.\n")
        f.write("\n")

        f.write("## Known Vendors with S3 Bucket Access\n\n")
        if s3_known_vendors:
            f.write("| Vendor | S3 Buckets |\n")
            f.write("|--------|----------|\n")
            for vendor, buckets in s3_known_vendors.items():
                f.write(f"| {vendor} | {', '.join(buckets)} |\n")
        else:
            f.write("No known vendors found in S3 bucket policies.\n")
        f.write("\n")

        f.write("## Unknown AWS Accounts with S3 Bucket Access\n\n")
        if s3_unknown_accounts:
            f.write("| AWS Account ID | Account Name | S3 Buckets |\n")
            f.write("|---------------|------------|----------|\n")
            for account_id, buckets in s3_unknown_accounts.items():
                account_name = account_aliases.get(account_id, "Unknown")
                f.write(f"| {account_id} | {account_name} | {', '.join(buckets)} |\n")
        else:
            f.write("No unknown AWS accounts found in S3 bucket policies.\n")

    return report_file


def _truncated_list(items: list[str], limit: int = 5) -> str:
    result = "\n".join(items[:limit])
    if len(items) > limit:
        result += "\n..."
    return result


def display_results(
    iam_known_vendors: dict[str, list[str]],
    iam_unknown_accounts: dict[str, list[str]],
    iam_trusted_entities: dict[str, dict[str, Any]],
    iam_vulnerable_roles: dict[str, dict[str, Any]],
    s3_known_vendors: dict[str, list[str]],
    s3_unknown_accounts: dict[str, list[str]],
    s3_trusted_entities: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
) -> None:
    """Display analysis results in formatted console tables."""
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "Unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    console.print(
        f"\n[cyan]Analyzing AWS Account:[/cyan] {current_account_id} ({current_account_alias})\n"
    )

    if iam_trusted_entities:
        table = Table(title="Trusted Entities with IAM Role Access", box=box.ROUNDED)
        table.add_column("Entity", style="green")
        table.add_column("Source", style="blue")
        table.add_column("IAM Roles", style="blue")
        for entity, data in iam_trusted_entities.items():
            table.add_row(entity, data["source"], _truncated_list(data["roles"]))
        console.print(table)

    if iam_known_vendors:
        table = Table(title="Known Vendors with IAM Role Access", box=box.ROUNDED)
        table.add_column("Vendor", style="cyan")
        table.add_column("IAM Roles", style="green")
        for vendor, roles in iam_known_vendors.items():
            table.add_row(vendor, _truncated_list(roles))
        console.print(table)

    if iam_unknown_accounts:
        table = Table(title="Unknown AWS Accounts with IAM Role Access", box=box.ROUNDED)
        table.add_column("AWS Account ID", style="yellow")
        table.add_column("IAM Roles", style="green")
        for account_id, roles in iam_unknown_accounts.items():
            table.add_row(account_id, _truncated_list(roles))
        console.print(table)

    if iam_vulnerable_roles:
        table = Table(
            title="IAM Roles Missing ExternalId Condition (Confused Deputy Risk)",
            box=box.ROUNDED,
        )
        table.add_column("Entity", style="red")
        table.add_column("Source", style="blue")
        table.add_column("Vulnerable IAM Roles", style="red")
        for entity, data in iam_vulnerable_roles.items():
            table.add_row(entity, data["source"], _truncated_list(data["roles"]))
        console.print(table)

    if s3_trusted_entities:
        table = Table(title="Trusted Entities with S3 Bucket Access", box=box.ROUNDED)
        table.add_column("Entity", style="green")
        table.add_column("Source", style="blue")
        table.add_column("S3 Buckets", style="blue")
        for entity, data in s3_trusted_entities.items():
            table.add_row(entity, data["source"], _truncated_list(data["buckets"]))
        console.print(table)

    if s3_known_vendors:
        table = Table(title="Known Vendors with S3 Bucket Access", box=box.ROUNDED)
        table.add_column("Vendor", style="cyan")
        table.add_column("S3 Buckets", style="green")
        for vendor, buckets in s3_known_vendors.items():
            table.add_row(vendor, _truncated_list(buckets))
        console.print(table)

    if s3_unknown_accounts:
        table = Table(title="Unknown AWS Accounts with S3 Bucket Access", box=box.ROUNDED)
        table.add_column("AWS Account ID", style="yellow")
        table.add_column("S3 Buckets", style="green")
        for account_id, buckets in s3_unknown_accounts.items():
            table.add_row(account_id, _truncated_list(buckets))
        console.print(table)

    total_trusted = len(iam_trusted_entities) + len(s3_trusted_entities)
    total_known = len(iam_known_vendors) + len(s3_known_vendors)
    total_unknown = len(iam_unknown_accounts) + len(s3_unknown_accounts)
    total_vulnerable = len(iam_vulnerable_roles)

    console.print(
        Panel(
            f"[bold]Summary:[/bold]\n"
            f"[green]Trusted entities found:[/green] {total_trusted}\n"
            f"[cyan]Known vendors found:[/cyan] {total_known}\n"
            f"[yellow]Unknown AWS accounts found:[/yellow] {total_unknown}\n"
            f"[red]Vulnerable IAM roles (missing ExternalId):[/red] {total_vulnerable}",
            title="AWS Trustline Results",
            box=box.ROUNDED,
        )
    )


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
    - ``auto`` keeps both but prefers ``ORGANIZATION`` per region when both
      exist (org coverage is a superset of account coverage).

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

            if scope == "auto":
                org = next(
                    (c for c in candidates if c["type"] == "ORGANIZATION"), None
                )
                chosen = org if org is not None else candidates[0]
            else:
                chosen = candidates[0]

            discovered[region] = chosen

    return discovered


def _principal_account_ids(principal: dict[str, str] | None) -> list[str]:
    """Extract account IDs from an Access Analyzer ``principal`` map.

    Access Analyzer findings carry a flat principal dict, typically shaped
    like ``{"AWS": "<arn-or-account>"}`` or ``{"Federated": "..."}``. Only
    values that reduce to a 12-digit account ID are returned.
    """
    if not principal:
        return []
    out: list[str] = []
    for value in principal.values():
        if not isinstance(value, str):
            continue
        acct = _extract_account_id_from_value(value)
        if acct:
            out.append(acct)
    return out


def _aa_finding_has_external_id(condition: dict[str, Any] | None) -> bool:
    """Return True if the AA finding's condition includes ``sts:ExternalId``.

    AA flattens the condition into a ``{condition_key: value}`` dict (it does
    not preserve the StringEquals/StringLike operator nesting), so a simple
    presence check is sufficient here.
    """
    if not condition:
        return False
    return any(isinstance(k, str) and k.lower() == "sts:externalid" for k in condition)


def _list_findings_in_region(
    session: boto3.Session,
    region: str,
    analyzer: dict[str, str],
    *,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
) -> tuple[str, list[dict[str, Any]] | None, str | None]:
    """Worker for parallel finding collection. Returns (region, findings, error)."""
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
                out.append(
                    _classify_aa_finding(
                        raw,
                        region=region,
                        analyzer_type=analyzer["type"],
                        account_to_vendor=account_to_vendor,
                        trusted_accounts=trusted_accounts,
                        account_aliases=account_aliases,
                        org_accounts=org_accounts,
                    )
                )
        return region, out, None
    except ClientError as e:
        return region, None, e.response["Error"]["Message"]
    except (BotoCoreError, Exception) as e:
        return region, None, str(e)


def collect_access_analyzer_findings(
    session: boto3.Session,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    analyzers: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Collect and classify findings from one or more external analyzers.

    Pages ACTIVE findings from each discovered analyzer in parallel (one
    worker per region under short timeouts) and produces a normalized data
    structure keyed by AWS resource type. Each finding is classified as
    ``trusted``, ``vendor``, ``unknown`` or ``public`` and, for IAM roles,
    flagged when ``sts:ExternalId`` is missing from the AA condition map.
    """
    findings_by_type: dict[str, list[dict[str, Any]]] = {}
    missing_external_id: list[dict[str, Any]] = []
    public_findings: list[dict[str, Any]] = []

    totals = {
        "trusted": 0,
        "vendors": 0,
        "unknown": 0,
        "public": 0,
        "missing_external_id": 0,
        "findings": 0,
        "regions": len(analyzers),
    }
    seen_owners: set[str] = set()

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
            ): region
            for region, analyzer in analyzers.items()
        }
        for future in as_completed(futures):
            region, findings, error = future.result()
            if error is not None:
                console.print(
                    f"[yellow]Warning: Could not list findings in {region}: "
                    f"{error}[/yellow]"
                )
                continue
            for finding in findings or []:
                totals["findings"] += 1

                classification = finding["classification"]
                if classification == "public":
                    totals["public"] += 1
                    public_findings.append(finding)
                elif classification == "trusted":
                    totals["trusted"] += 1
                elif classification == "vendor":
                    totals["vendors"] += 1
                else:
                    totals["unknown"] += 1

                if finding.get("missing_external_id"):
                    totals["missing_external_id"] += 1
                    missing_external_id.append(finding)

                if finding.get("resource_owner"):
                    seen_owners.add(finding["resource_owner"])

                findings_by_type.setdefault(
                    finding["resource_type"], []
                ).append(finding)

    totals["owner_accounts"] = len(seen_owners)

    return {
        "by_resource_type": findings_by_type,
        "missing_external_id": missing_external_id,
        "public_findings": public_findings,
        "totals": totals,
        "analyzers": analyzers,
        "owner_accounts": sorted(seen_owners),
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
) -> dict[str, Any]:
    """Normalize and classify a single Access Analyzer finding.

    Public findings short-circuit ahead of the principal-based classification
    because Access Analyzer reports ``isPublic == True`` with an empty or
    wildcard principal map.
    """
    resource_type = raw.get("resourceType", "Unknown")
    resource = raw.get("resource", "")
    resource_owner = raw.get("resourceOwnerAccount", "")
    is_public = bool(raw.get("isPublic", False))
    actions = raw.get("action") or []
    condition = raw.get("condition") or {}
    finding_id = raw.get("id", "")
    principal = raw.get("principal") or {}

    principal_accounts = _principal_account_ids(principal)
    external_principal = principal_accounts[0] if principal_accounts else ""

    classification = "unknown"
    vendor_info: dict[str, Any] | None = None
    trusted_info: dict[str, Any] | None = None

    if is_public:
        classification = "public"
    elif external_principal:
        if external_principal in trusted_accounts:
            classification = "trusted"
            trusted_info = trusted_accounts[external_principal]
        elif external_principal in account_to_vendor:
            classification = "vendor"
            vendor_info = account_to_vendor[external_principal]
    else:
        # No AWS account principal (e.g. federated, service or canonical user).
        # Treat as unknown so it surfaces in the report.
        classification = "unknown"

    owner_label = ""
    if resource_owner:
        owner_label = resource_owner
        if resource_owner in org_accounts:
            owner_label = f"{resource_owner} ({org_accounts[resource_owner]['name']})"
        elif resource_owner in account_aliases:
            owner_label = f"{resource_owner} ({account_aliases[resource_owner]})"

    principal_label = ""
    if is_public:
        principal_label = "Everyone (public)"
    elif external_principal:
        principal_label = external_principal
        if external_principal in account_aliases:
            principal_label = (
                f"{external_principal} ({account_aliases[external_principal]})"
            )
    elif principal:
        # Show the raw principal type so federated / service principals are visible.
        kind, value = next(iter(principal.items()))
        principal_label = f"{kind}: {value}"

    finding: dict[str, Any] = {
        "id": finding_id,
        "region": region,
        "analyzer_type": analyzer_type,
        "resource": resource,
        "resource_type": resource_type,
        "resource_owner": resource_owner,
        "owner_label": owner_label,
        "external_principal": external_principal,
        "principal_label": principal_label,
        "principal_raw": principal,
        "is_public": is_public,
        "actions": actions,
        "condition": condition,
        "classification": classification,
        "vendor": vendor_info,
        "trusted": trusted_info,
    }

    if resource_type == "AWS::IAM::Role" and not is_public and external_principal:
        # Re-derive the confused-deputy signal from AA's condition map.
        if not _aa_finding_has_external_id(condition):
            finding["missing_external_id"] = True

    return finding


def display_aa_results(report_data: dict[str, Any]) -> None:
    """Render the Access Analyzer findings to the console with rich."""
    totals = report_data["totals"]
    analyzers = report_data["analyzers"]
    by_type = report_data["by_resource_type"]

    console.print(
        Panel(
            f"[bold]Access Analyzer Summary[/bold]\n"
            f"[blue]Regions analyzed:[/blue] {totals['regions']}\n"
            f"[blue]Owner accounts seen:[/blue] {totals['owner_accounts']}\n"
            f"[green]Trusted findings:[/green] {totals['trusted']}\n"
            f"[cyan]Known vendor findings:[/cyan] {totals['vendors']}\n"
            f"[yellow]Unknown principal findings:[/yellow] {totals['unknown']}\n"
            f"[red]Public access findings:[/red] {totals['public']}\n"
            f"[red]IAM roles missing ExternalId:[/red] {totals['missing_external_id']}\n"
            f"[bold]Total findings:[/bold] {totals['findings']}",
            title="AWS Trustline (Access Analyzer)",
            box=box.ROUNDED,
        )
    )

    if not by_type:
        console.print(
            "[green]No active external-access findings reported by any analyzer.[/green]"
        )
        return

    for region, analyzer in analyzers.items():
        console.print(
            f"[dim]Analyzer in {region}: {analyzer['name']} "
            f"({analyzer['type']})[/dim]"
        )

    for resource_type in sorted(by_type.keys()):
        items = by_type[resource_type]
        label = AA_RESOURCE_TYPE_LABELS.get(resource_type, resource_type)
        table = Table(title=f"{label} ({len(items)} finding(s))", box=box.ROUNDED)
        table.add_column("Resource", style="cyan", overflow="fold")
        table.add_column("Owner", style="blue")
        table.add_column("External principal", style="yellow")
        table.add_column("Classification", style="green")
        table.add_column("Region", style="dim")
        for f in items:
            classification = f["classification"]
            display = classification
            if classification == "vendor" and f["vendor"]:
                display = f"vendor: {f['vendor']['name']}"
            elif classification == "trusted" and f["trusted"]:
                display = f"trusted: {f['trusted']['name']}"
            elif classification == "public":
                display = "[bold red]public[/bold red]"
            table.add_row(
                _short_resource(f["resource"]),
                f["owner_label"] or "-",
                f["principal_label"] or "-",
                display,
                f["region"],
            )
        console.print(table)

    if report_data["missing_external_id"]:
        table = Table(
            title="IAM Roles Missing ExternalId Condition (Confused Deputy Risk)",
            box=box.ROUNDED,
        )
        table.add_column("Role", style="red", overflow="fold")
        table.add_column("Owner", style="blue")
        table.add_column("External principal", style="yellow")
        table.add_column("Region", style="dim")
        for f in report_data["missing_external_id"]:
            table.add_row(
                _short_resource(f["resource"]),
                f["owner_label"] or "-",
                f["principal_label"] or "-",
                f["region"],
            )
        console.print(table)


def _short_resource(arn_or_name: str) -> str:
    """Trim an ARN to its last path segment for compact console rendering."""
    if not arn_or_name:
        return ""
    if "/" in arn_or_name:
        return arn_or_name.split("/")[-1]
    if ":" in arn_or_name:
        return arn_or_name.split(":")[-1]
    return arn_or_name


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
    return _html_pill("unknown", "warn")


def _html_principal_cell(finding: dict[str, Any]) -> str:
    if finding["is_public"]:
        return '<span class="dim mono">Everyone (public)</span>'
    label = finding.get("principal_label") or ""
    if not label:
        return '<span class="dim">-</span>'
    return f'<span class="mono">{_h(label)}</span>'


def _html_resource_cell(finding: dict[str, Any]) -> str:
    arn = finding.get("resource", "")
    region = finding.get("region", "")
    return (
        '<div class="resource-cell">'
        f'<div class="arn">{_h(arn) or "-"}</div>'
        f'<div class="region">{_h(region)}</div>'
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


def _aa_meta_row(report_data: dict[str, Any], account_label: str, scope: str) -> str:
    analyzers = report_data["analyzers"]
    regions = ", ".join(analyzers.keys()) if analyzers else "-"
    items = [
        f"<span><strong>Account/Org:</strong> {_h(account_label)}</span>",
        f"<span><strong>Scope:</strong> {_h(scope)}</span>",
        f"<span><strong>Regions:</strong> {_h(regions)}</span>",
        f"<span><strong>Owner accounts:</strong> {report_data['totals']['owner_accounts']}</span>",
        f"<span><strong>Generated:</strong> {_h(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</span>",
    ]
    return f'<div class="meta meta-row">{"".join(items)}</div>'


def generate_html_report_aa(
    report_data: dict[str, Any],
    *,
    account_aliases: dict[str, str],
    org_accounts: dict[str, dict[str, Any]],
    scope: str,
    output_dir: str = ".",
) -> str:
    """Write an Access Analyzer findings report as a self-contained HTML file."""
    totals = report_data["totals"]
    by_type = report_data["by_resource_type"]

    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    if scope == "organization":
        identity_slug = "org"
        identity_label = f"AWS Organization ({totals['owner_accounts']} accounts)"
    else:
        identity_slug = current_account_id
        identity_label = f"{current_account_id} ({current_account_alias})"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(
        output_dir, f"trustline_report_{identity_slug}_{timestamp}.html"
    )

    show_owner_column = scope == "organization"

    header_html = (
        f'<div class="nav-meta">{_h(identity_label)}'
        f' &middot; {_h(scope)} scope</div>'
    )

    hero_html = (
        '<section class="hero"><div>'
        '<h1>Trustline<span style="color:var(--accent)">_</span>'
        '<span class="badge">Access Analyzer</span></h1>'
        '<p>Provable external-access findings, classified against the '
        '<a href="https://github.com/fwdcloudsec/known_aws_accounts" target="_blank" rel="noopener noreferrer">fwd:cloudsec</a> '
        'vendor dataset.</p>'
        f"{_aa_meta_row(report_data, identity_label, scope)}"
        "</div></section>"
    )

    kpis_html = (
        '<div class="kpis">'
        + _render_kpi("Trusted", totals["trusted"], "From Org + YAML allow-list")
        + _render_kpi("Known vendors", totals["vendors"], "From fwd:cloudsec dataset")
        + _render_kpi("Unknown", totals["unknown"], "External principals to review", danger=totals["unknown"] > 0)
        + _render_kpi("Public", totals["public"], "Resources open to the world", danger=totals["public"] > 0)
        + _render_kpi(
            "Missing ExternalId",
            totals["missing_external_id"],
            "IAM roles at confused-deputy risk",
            danger=totals["missing_external_id"] > 0,
        )
        + _render_kpi("Total findings", totals["findings"], f"Across {totals['regions']} region(s)")
        + "</div>"
    )

    sections_html_parts: list[str] = []

    if report_data["public_findings"]:
        rows = "".join(
            "<tr>"
            f"<td>{AA_RESOURCE_TYPE_LABELS.get(f['resource_type'], f['resource_type'])}</td>"
            f"<td>{_html_resource_cell(f)}</td>"
            + (f'<td><span class="mono">{_h(f["owner_label"] or "-")}</span></td>' if show_owner_column else "")
            + f"<td>{_html_actions_cell(f.get('actions', []))}</td>"
            "</tr>"
            for f in report_data["public_findings"]
        )
        columns = ["Type", "Resource"]
        if show_owner_column:
            columns.append("Owner")
        columns.append("Actions")
        sections_html_parts.append(
            _render_section(
                "Public access",
                rows,
                columns,
                subtitle=f"{len(report_data['public_findings'])} resource(s) shared with everyone",
            )
        )

    if report_data["missing_external_id"]:
        rows = "".join(
            "<tr>"
            f"<td>{_html_resource_cell(f)}</td>"
            + (f'<td><span class="mono">{_h(f["owner_label"] or "-")}</span></td>' if show_owner_column else "")
            + f"<td>{_html_principal_cell(f)}</td>"
            f"<td>{_html_classification_pill(f)}</td>"
            "</tr>"
            for f in report_data["missing_external_id"]
        )
        columns = ["IAM Role"]
        if show_owner_column:
            columns.append("Owner")
        columns.extend(["External principal", "Classification"])
        sections_html_parts.append(
            _render_section(
                "IAM roles missing ExternalId condition",
                rows,
                columns,
                subtitle="Cross-account trust without sts:ExternalId condition (confused deputy risk)",
            )
        )

    for resource_type in sorted(by_type.keys()):
        items = by_type[resource_type]
        label = AA_RESOURCE_TYPE_LABELS.get(resource_type, resource_type)
        rows = "".join(
            "<tr>"
            f"<td>{_html_resource_cell(f)}</td>"
            + (f'<td><span class="mono">{_h(f["owner_label"] or "-")}</span></td>' if show_owner_column else "")
            + f"<td>{_html_principal_cell(f)}</td>"
            f"<td>{_html_classification_pill(f)}</td>"
            f"<td>{_html_pill('public', 'danger') if f['is_public'] else '<span class=\"dim\">-</span>'}</td>"
            f"<td>{_html_actions_cell(f.get('actions', []))}</td>"
            "</tr>"
            for f in items
        )
        columns = ["Resource"]
        if show_owner_column:
            columns.append("Owner")
        columns.extend(["External principal", "Classification", "Public", "Actions"])
        sections_html_parts.append(
            _render_section(
                f"{label}",
                rows,
                columns,
                subtitle=f"{len(items)} finding(s)",
                neutral=True,
            )
        )

    if not sections_html_parts:
        sections_html_parts.append(
            '<div class="callout">No active external-access findings reported by any analyzer in scope. '
            "Either no resources are shared externally, or the analyzers have not yet produced findings "
            "(findings are generated asynchronously after analyzer creation).</div>"
        )

    body_html = hero_html + kpis_html + "\n".join(sections_html_parts)

    with open(report_file, "w") as f:
        f.write(
            _html_document(
                title=f"Trustline Report - {identity_label}",
                header_html=header_html,
                body_html=body_html,
            )
        )

    return report_file


def generate_html_report_legacy(
    iam_known_vendors: dict[str, list[str]],
    iam_unknown_accounts: dict[str, list[str]],
    iam_trusted_entities: dict[str, dict[str, Any]],
    iam_vulnerable_roles: dict[str, dict[str, Any]],
    s3_known_vendors: dict[str, list[str]],
    s3_unknown_accounts: dict[str, list[str]],
    s3_trusted_entities: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    *,
    output_dir: str = ".",
    org_error: str | None = None,
) -> str:
    """Write the regex-backend findings as a self-contained HTML report.

    Mirrors the structure of :func:`generate_report` (the Markdown writer) but
    rendered with the same iamtrail.com design system used by the Access
    Analyzer report so users get a consistent look across backends.
    """
    current_account_id = (
        list(account_aliases.keys())[0] if account_aliases else "unknown"
    )
    current_account_alias = account_aliases.get(current_account_id, current_account_id)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(
        output_dir, f"trustline_report_{current_account_id}_{timestamp}.html"
    )

    total_trusted = len(iam_trusted_entities) + len(s3_trusted_entities)
    total_known = len(iam_known_vendors) + len(s3_known_vendors)
    total_unknown = len(iam_unknown_accounts) + len(s3_unknown_accounts)
    total_vulnerable = len(iam_vulnerable_roles)

    header_html = (
        f'<div class="nav-meta">{_h(current_account_id)} ({_h(current_account_alias)})</div>'
    )

    hero_html = (
        '<section class="hero"><div>'
        '<h1>Trustline<span style="color:var(--accent)">_</span>'
        '<span class="badge">Policy scanner</span></h1>'
        '<p>Map and audit third-party trust in IAM role trust policies and S3 bucket policies.</p>'
        '<div class="meta meta-row">'
        f"<span><strong>Account:</strong> {_h(current_account_id)} ({_h(current_account_alias)})</span>"
        f"<span><strong>Generated:</strong> {_h(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</span>"
        "</div>"
        "</div></section>"
    )

    kpis_html = (
        '<div class="kpis">'
        + _render_kpi("Trusted entities", total_trusted)
        + _render_kpi("Known vendors", total_known)
        + _render_kpi("Unknown accounts", total_unknown, danger=total_unknown > 0)
        + _render_kpi("Missing ExternalId", total_vulnerable, "Confused deputy risk", danger=total_vulnerable > 0)
        + "</div>"
    )

    sections: list[str] = []

    if org_error:
        sections.append(
            '<div class="callout"><strong>AWS Organizations:</strong> '
            f"could not list accounts ({_h(org_error)}). "
            "Trusted-entity matches may be incomplete; ensure the caller has "
            "<code>organizations:ListAccounts</code>.</div>"
        )

    sections.append("<h2 style=\"font-family:var(--mono);margin:32px 0 8px;\">IAM Roles</h2>")

    rows = "".join(
        "<tr>"
        f"<td>{_h(entity)}</td>"
        f"<td>{_html_pill(data['source'])}</td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(r)}</span>' for r in data['roles'])}</div></td>"
        "</tr>"
        for entity, data in iam_trusted_entities.items()
    )
    sections.append(
        _render_section(
            "Trusted entities with IAM role access",
            rows,
            ["Entity", "Source", "Roles"],
            empty_message="No trusted entities found in IAM role trust policies.",
            neutral=True,
        )
    )

    rows = "".join(
        "<tr>"
        f"<td>{_h(vendor)}</td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(r)}</span>' for r in roles)}</div></td>"
        "</tr>"
        for vendor, roles in iam_known_vendors.items()
    )
    sections.append(
        _render_section(
            "Known vendors with IAM role access",
            rows,
            ["Vendor", "Roles"],
            empty_message="No known vendors found in IAM role trust policies.",
            neutral=True,
        )
    )

    rows = "".join(
        "<tr>"
        f"<td><span class=\"mono\">{_h(account)}</span></td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(r)}</span>' for r in roles)}</div></td>"
        "</tr>"
        for account, roles in iam_unknown_accounts.items()
    )
    sections.append(
        _render_section(
            "Unknown AWS accounts with IAM role access",
            rows,
            ["Account", "Roles"],
            empty_message="No unknown AWS accounts found in IAM role trust policies.",
        )
    )

    rows = "".join(
        "<tr>"
        f"<td>{_h(entity)}</td>"
        f"<td>{_html_pill(data['source'])}</td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(r)}</span>' for r in data['roles'])}</div></td>"
        "</tr>"
        for entity, data in iam_vulnerable_roles.items()
    )
    sections.append(
        _render_section(
            "IAM roles missing ExternalId condition",
            rows,
            ["Entity", "Source", "Vulnerable roles"],
            subtitle="Cross-account roles at risk of the confused deputy problem",
            empty_message="No vulnerable IAM roles found.",
        )
    )

    sections.append("<h2 style=\"font-family:var(--mono);margin:32px 0 8px;\">S3 Buckets</h2>")

    rows = "".join(
        "<tr>"
        f"<td>{_h(entity)}</td>"
        f"<td>{_html_pill(data['source'])}</td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(b)}</span>' for b in data['buckets'])}</div></td>"
        "</tr>"
        for entity, data in s3_trusted_entities.items()
    )
    sections.append(
        _render_section(
            "Trusted entities with S3 bucket access",
            rows,
            ["Entity", "Source", "Buckets"],
            empty_message="No trusted entities found in S3 bucket policies.",
            neutral=True,
        )
    )

    rows = "".join(
        "<tr>"
        f"<td>{_h(vendor)}</td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(b)}</span>' for b in buckets)}</div></td>"
        "</tr>"
        for vendor, buckets in s3_known_vendors.items()
    )
    sections.append(
        _render_section(
            "Known vendors with S3 bucket access",
            rows,
            ["Vendor", "Buckets"],
            empty_message="No known vendors found in S3 bucket policies.",
            neutral=True,
        )
    )

    rows = "".join(
        "<tr>"
        f"<td><span class=\"mono\">{_h(account)}</span></td>"
        f"<td><div class=\"tags\">{''.join(f'<span class=\"tag\">{_h(b)}</span>' for b in buckets)}</div></td>"
        "</tr>"
        for account, buckets in s3_unknown_accounts.items()
    )
    sections.append(
        _render_section(
            "Unknown AWS accounts with S3 bucket access",
            rows,
            ["Account", "Buckets"],
            empty_message="No unknown AWS accounts found in S3 bucket policies.",
        )
    )

    body_html = hero_html + kpis_html + "\n".join(sections)

    with open(report_file, "w") as f:
        f.write(
            _html_document(
                title=f"Trustline Report - {current_account_id}",
                header_html=header_html,
                body_html=body_html,
            )
        )

    return report_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustline",
        description="AWS Trustline - Map and audit third-party trust relationships in your AWS account.",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-p", "--profile",
        help="AWS profile name to use for authentication",
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region to use (overrides profile/env default)",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT_DIR,
        help=(
            f"Output directory for report files (default: {DEFAULT_OUTPUT_DIR}/). "
            "Each run writes a timestamped, account/org-scoped file. Existing "
            "reports are never overwritten."
        ),
    )
    parser.add_argument(
        "-t", "--trusted-accounts",
        default=DEFAULT_TRUSTED_ACCOUNTS_FILE,
        help=f"Path to trusted accounts YAML file (default: {DEFAULT_TRUSTED_ACCOUNTS_FILE})",
    )
    parser.add_argument(
        "--skip-s3",
        action="store_true",
        help="Skip S3 bucket policy analysis (regex backend only)",
    )
    parser.add_argument(
        "--skip-iam",
        action="store_true",
        help="Skip IAM role trust policy analysis (regex backend only)",
    )
    parser.add_argument(
        "--use-access-analyzer",
        action="store_true",
        help=(
            "Use IAM Access Analyzer findings instead of the built-in regex "
            "scanner (covers all AA-supported resource types: IAM, S3, KMS, "
            "Lambda, SNS, SQS, Secrets Manager, EFS, EBS/RDS snapshots, ECR, "
            "DynamoDB)"
        ),
    )
    parser.add_argument(
        "--scope",
        choices=["auto", "account", "organization"],
        default="auto",
        help=(
            "Access Analyzer scope: 'account' uses ACCOUNT analyzers, "
            "'organization' uses ORGANIZATION analyzers (run from the org "
            "management or AA delegated-admin account), 'auto' prefers an "
            "ORGANIZATION analyzer when present (default: auto)"
        ),
    )
    region_group = parser.add_mutually_exclusive_group()
    region_group.add_argument(
        "--regions",
        help=(
            "Comma-separated regions for the Access Analyzer backend "
            "(e.g. us-east-1,eu-west-1). Defaults to the session region."
        ),
    )
    region_group.add_argument(
        "--all-regions",
        action="store_true",
        help=(
            "Enumerate every enabled region via ec2:DescribeRegions "
            "and query an external analyzer in each (Access Analyzer backend only)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["html", "md", "both"],
        default=None,
        help=(
            "Report format(s) to write. Default: 'html' for the Access "
            "Analyzer backend, 'md' for the regex backend."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full error tracebacks for debugging",
    )
    return parser


def _resolve_format(args: argparse.Namespace) -> str:
    """Default ``--format`` per backend (HTML for AA, Markdown for the regex)."""
    if args.format:
        return args.format
    return "html" if args.use_access_analyzer else "md"


def _run_access_analyzer_backend(
    session: boto3.Session,
    args: argparse.Namespace,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    org_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    output_format: str,
) -> int:
    """Drive the Access Analyzer pipeline: region resolve, discover, collect, render."""
    try:
        regions = resolve_regions(session, args)
    except (ValueError, RuntimeError) as e:
        console.print(f"[bold red]Error resolving regions: {e}[/bold red]")
        return 1

    console.print(
        f"[bold]Discovering external analyzers in {len(regions)} region(s) "
        f"(scope: {args.scope})...[/bold]"
    )
    analyzers = find_external_analyzers(session, regions, args.scope)

    missing = [r for r in regions if r not in analyzers]
    if missing:
        console.print(
            f"[yellow]No matching external analyzer in: "
            f"{', '.join(missing)}[/yellow]"
        )

    if not analyzers:
        scope_hint = "ORGANIZATION" if args.scope == "organization" else "ACCOUNT"
        console.print(
            "[bold red]No external Access Analyzer found in any requested "
            "region.[/bold red]"
        )
        console.print(
            "[yellow]Create a free external-access analyzer with:[/yellow]"
        )
        console.print(
            f"  [cyan]aws accessanalyzer create-analyzer "
            f"--analyzer-name trustline --type {scope_hint}[/cyan]"
        )
        if args.scope in ("organization", "auto"):
            console.print(
                "  [dim](ORGANIZATION analyzers must be created from the org "
                "management or AA delegated-admin account.)[/dim]"
            )
        return 1

    for region, analyzer in analyzers.items():
        console.print(
            f"[green]Found {analyzer['type']} analyzer in {region}: "
            f"{analyzer['name']}[/green]"
        )

    report_data = collect_access_analyzer_findings(
        session=session,
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
        analyzers=analyzers,
    )

    display_aa_results(report_data)

    os.makedirs(args.output, exist_ok=True)

    effective_scope = args.scope
    if effective_scope == "auto":
        if any(a["type"] == "ORGANIZATION" for a in analyzers.values()):
            effective_scope = "organization"
        else:
            effective_scope = "account"

    if output_format in ("html", "both"):
        html_path = generate_html_report_aa(
            report_data,
            account_aliases=account_aliases,
            org_accounts=org_accounts,
            scope=effective_scope,
            output_dir=args.output,
        )
        console.print(f"\n[bold green]HTML report: {html_path}[/bold green]")

    if output_format in ("md", "both"):
        console.print(
            "[yellow]Note: Markdown output is not implemented for the Access "
            "Analyzer backend yet; only HTML is produced.[/yellow]"
        )

    return 0


def _run_regex_backend(
    session: boto3.Session,
    args: argparse.Namespace,
    account_to_vendor: dict[str, dict[str, Any]],
    trusted_accounts: dict[str, dict[str, Any]],
    account_aliases: dict[str, str],
    org_error: str | None,
    output_format: str,
) -> int:
    """Drive the original IAM/S3 regex scanner pipeline."""
    iam_known_vendors: dict = {}
    iam_unknown_accounts: dict = {}
    iam_trusted_entities: dict = {}
    iam_vulnerable_roles: dict = {}

    if not args.skip_iam:
        (
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
        ) = check_iam_role_trust_policies(
            session, account_to_vendor, trusted_accounts, account_aliases
        )

    s3_known_vendors: dict = {}
    s3_unknown_accounts: dict = {}
    s3_trusted_entities: dict = {}

    if not args.skip_s3:
        s3_known_vendors, s3_unknown_accounts, s3_trusted_entities = (
            check_s3_bucket_policies(
                session, account_to_vendor, trusted_accounts, account_aliases
            )
        )

    display_results(
        iam_known_vendors,
        iam_unknown_accounts,
        iam_trusted_entities,
        iam_vulnerable_roles,
        s3_known_vendors,
        s3_unknown_accounts,
        s3_trusted_entities,
        account_aliases,
    )

    os.makedirs(args.output, exist_ok=True)

    if output_format in ("md", "both"):
        md_path = generate_report(
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
            s3_known_vendors,
            s3_unknown_accounts,
            s3_trusted_entities,
            account_aliases,
            output_dir=args.output,
            org_error=org_error,
        )
        console.print(f"\n[bold green]Markdown report: {md_path}[/bold green]")

    if output_format in ("html", "both"):
        html_path = generate_html_report_legacy(
            iam_known_vendors,
            iam_unknown_accounts,
            iam_trusted_entities,
            iam_vulnerable_roles,
            s3_known_vendors,
            s3_unknown_accounts,
            s3_trusted_entities,
            account_aliases,
            output_dir=args.output,
            org_error=org_error,
        )
        console.print(f"[bold green]HTML report: {html_path}[/bold green]")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.use_access_analyzer and (args.skip_iam or args.skip_s3):
        console.print(
            "[bold red]Error: --use-access-analyzer is mutually exclusive with "
            "--skip-iam / --skip-s3.[/bold red]"
        )
        return 1

    if not args.use_access_analyzer and (args.regions or args.all_regions):
        console.print(
            "[bold red]Error: --regions / --all-regions require "
            "--use-access-analyzer.[/bold red]"
        )
        return 1

    if not args.use_access_analyzer and args.skip_iam and args.skip_s3:
        console.print("[bold red]Error: Cannot skip both IAM and S3 analysis.[/bold red]")
        return 1

    session_kwargs: dict[str, str] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region
    session = boto3.Session(**session_kwargs)

    output_format = _resolve_format(args)

    try:
        backend_label = "Access Analyzer" if args.use_access_analyzer else "Policy scanner"
        console.print(
            Panel(
                "[bold cyan]AWS Trustline[/bold cyan]\n"
                "Map and audit third-party trust relationships in your AWS account.\n"
                f"[dim]Backend:[/dim] {backend_label}    "
                f"[dim]Output:[/dim] {output_format}",
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

        # Keep the raw Org-only map for AA scope grouping/labels.
        org_accounts: dict[str, dict[str, Any]] = {
            acct_id: meta
            for acct_id, meta in trusted_accounts.items()
            if meta.get("source") == "aws_org"
        }

        account_aliases = get_account_aliases(session)

        if args.use_access_analyzer:
            return _run_access_analyzer_backend(
                session=session,
                args=args,
                account_to_vendor=account_to_vendor,
                trusted_accounts=trusted_accounts,
                org_accounts=org_accounts,
                account_aliases=account_aliases,
                output_format=output_format,
            )

        return _run_regex_backend(
            session=session,
            args=args,
            account_to_vendor=account_to_vendor,
            trusted_accounts=trusted_accounts,
            account_aliases=account_aliases,
            org_error=org_error,
            output_format=output_format,
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
