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
import json
import os
import re
import sys
from datetime import datetime
from typing import Any

import boto3
import requests
import yaml
from botocore.exceptions import ClientError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

__version__ = "0.1.0"

REFERENCE_DATA_URL = (
    "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
)
DEFAULT_TRUSTED_ACCOUNTS_FILE = "trusted_accounts.yaml"
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

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
                "To fix this, ensure your IAM user/role has the `organizations:ListAccounts` permission.\n\n"
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
        default=".",
        help="Output directory for the report file (default: current directory)",
    )
    parser.add_argument(
        "-t", "--trusted-accounts",
        default=DEFAULT_TRUSTED_ACCOUNTS_FILE,
        help=f"Path to trusted accounts YAML file (default: {DEFAULT_TRUSTED_ACCOUNTS_FILE})",
    )
    parser.add_argument(
        "--skip-s3",
        action="store_true",
        help="Skip S3 bucket policy analysis",
    )
    parser.add_argument(
        "--skip-iam",
        action="store_true",
        help="Skip IAM role trust policy analysis",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full error tracebacks for debugging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.skip_iam and args.skip_s3:
        console.print("[bold red]Error: Cannot skip both IAM and S3 analysis.[/bold red]")
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
                "Map and audit third-party trust relationships in your AWS account.\n"
                "Analyzes IAM Role trust policies and S3 bucket policies to identify\n"
                "external vendors with access to your resources.",
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

        account_aliases = get_account_aliases(session)

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

        report_file = generate_report(
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
        console.print(f"\n[bold green]Report generated: {report_file}[/bold green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
