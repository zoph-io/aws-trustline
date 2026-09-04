# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Victor Grenu / zoph.io
"""Grant-row model and principal classification for AWS Trustline.

A grant is one resource giving access to one principal through one mechanism.
Vendor / org / YAML data classify the row; they are not grouping keys.

Account IDs found inside federated or Organizations ARNs are *not* treated as
the external party. The account ID in a GitHub OIDC provider ARN is yours.
An OrganizationArn on an AMI is not proof the share is internal.
CloudFront origin access identities use ``iam::cloudfront:user/…`` — that is
AWS, not an unknown third party.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
# Organizations ARNs carry the management-account ID in the account slot.
# That ID is not the grantee. Match before any generic ARN account extract.
ORGANIZATIONS_ARN_RE = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:organizations::(\d{12}):(organization|ou)/(.+)$"
)
IAM_ARN_RE = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:iam::(\d{12}):.+$"
)
# S3 bucket policies name CloudFront OAIs/OACs this way. The account slot is
# the literal "cloudfront", not a 12-digit ID.
CLOUDFRONT_IAM_USER_RE = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:iam::cloudfront:user/(.+)$",
    re.IGNORECASE,
)
GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"
GITLAB_OIDC_MARKERS = ("gitlab.com", "gitlab.")

# AWS-owned accounts that show up as "strangers" in share attributes.
# Community known_aws_accounts wins on conflict.
BUILTIN_VENDOR_ACCOUNTS: dict[str, dict[str, Any]] = {
    "784127676232": {
        "name": "Amazon Redshift Support",
        "type": "aws-support",
        "source": [
            "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html"
        ],
    },
}

# Surfaces this tool does not scan. Printed so a green report is not a lie.
OUT_OF_SCOPE_SURFACES: tuple[tuple[str, str], ...] = (
    (
        "Lake Formation grants",
        "Permission lives in Lake Formation / RAM, not on the S3 bucket",
    ),
    (
        "Kafka ACLs on MSK",
        "Stored in the cluster; no AWS API and CloudTrail does not see them",
    ),
    (
        "OpenSearch fine-grained access control",
        "Internal security plugin, not the domain access policy",
    ),
    (
        "OpenSearch Serverless data access policies",
        "Collection-level data access, not a domain resource policy",
    ),
    (
        "PrivateLink allowed principals",
        "VPC endpoint service configuration, not a resource policy",
    ),
    (
        "Route 53 VPC association authorizations",
        "Trusts a VPC ID, not an account; deleting the authorization leaves the association",
    ),
    (
        "Copies, replication, and DLM share rules",
        "The record in your account does not name who will use the copy",
    ),
    (
        "SES sending authorization",
        "Out of scope for this release",
    ),
)

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

AA_SUPPORTED_TYPES: tuple[str, ...] = tuple(AA_RESOURCE_TYPE_LABELS.keys())

SERVICE_SPECIFIC_CREDENTIAL_SERVICES: tuple[str, ...] = (
    "codecommit.amazonaws.com",
    "cassandra.amazonaws.com",
    "bedrock.amazonaws.com",
    "logs.amazonaws.com",
    "cloudwatch.amazonaws.com",
    "aws-external-anthropic.amazonaws.com",
)

MECHANISM_LABELS: dict[str, str] = {
    "trust_policy": "IAM role trust policy",
    "s3_bucket_policy": "S3 bucket policy",
    "ram_share": "RAM resource share",
    "ami_launch_permission": "AMI launch permission",
    "ssm_document_share": "SSM document share",
    "service_specific_credential": "IAM service-specific credential",
    "access_analyzer": "Access Analyzer finding",
    "kms_key_policy": "KMS key policy",
    "sns_topic_policy": "SNS topic policy",
    "sqs_queue_policy": "SQS queue policy",
    "lambda_resource_policy": "Lambda resource policy",
    "secretsmanager_resource_policy": "Secrets Manager resource policy",
    "ecr_repository_policy": "ECR repository policy",
    "lambda_layer_policy": "Lambda layer permission",
    "kms_grant": "KMS cryptographic grant",
    "eventbridge_bus_policy": "EventBridge bus policy",
    "glue_catalog_policy": "Glue Data Catalog resource policy",
    "opensearch_domain_policy": "OpenSearch domain access policy",
}

# Where a principal's display name came from. Reports print these labels.
NAME_SOURCE_LABELS: dict[str, str] = {
    "fwd:cloudsec": "fwd:cloudsec",
    "aws_builtin": "AWS docs (builtin)",
    "yaml_file": "trusted_accounts.yaml",
    "aws_org": "AWS Organizations",
    "aws_cloudfront": "Amazon CloudFront",
    "not_in_dataset": "not in known_aws_accounts",
    "federated": "federated (no account ID)",
    "public": "everyone (*)",
    "blocked_by_bpa": "blocked by Block Public Access",
    "unresolved": "unresolved",
}

_PARTY_CLASS_RANK = {
    "unknown": 0,
    "public": 1,
    "vendor": 2,
    "federated": 3,
    "trusted": 4,
}


def merge_builtin_vendors(
    account_to_vendor: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Overlay AWS-owned aliases that are missing from the community list."""
    merged = dict(account_to_vendor)
    for account_id, meta in BUILTIN_VENDOR_ACCOUNTS.items():
        if account_id not in merged:
            merged[account_id] = dict(meta)
    return merged


def extract_account_id_from_iam_value(value: str) -> str | None:
    """Return a 12-digit account ID from a raw id or IAM/STS principal ARN.

    Returns None for Organizations ARNs, federated provider ARNs (callers must
    not use this helper on Federated principals), wildcards, and service names.
    """
    if not isinstance(value, str) or not value:
        return None
    value = value.strip()
    if value in ("*", "all", "All"):
        return None
    org_match = ORGANIZATIONS_ARN_RE.match(value)
    if org_match:
        return None
    if ":oidc-provider/" in value or ":saml-provider/" in value:
        return None
    if ":iam::cloudfront:" in value.lower():
        return None
    iam_match = IAM_ARN_RE.match(value)
    if iam_match:
        return iam_match.group(1)
    if ACCOUNT_ID_PATTERN.match(value):
        return value
    # Generic ARN account slot, but not organizations / oidc / saml (above).
    if value.startswith("arn:"):
        parts = value.split(":")
        if len(parts) >= 5 and ACCOUNT_ID_PATTERN.match(parts[4]):
            return parts[4]
    return None


def is_aws_service_principal(value: str) -> bool:
    """True for AWS service principals (lambda.amazonaws.com, etc.)."""
    if not isinstance(value, str):
        return False
    lowered = value.lower().strip()
    if lowered.endswith(".amazonaws.com") and not lowered.startswith("arn:"):
        return True
    return False


def cloudfront_principal_label(resource_path: str) -> str:
    """Short label for an ``iam::cloudfront:user/…`` principal."""
    lowered = resource_path.lower()
    token = resource_path.rsplit(" ", 1)[-1]
    if "origin access identity" in lowered:
        return f"CloudFront OAI {token}"
    if "origin access control" in lowered:
        return f"CloudFront OAC {token}"
    return f"CloudFront {resource_path}"


def federated_provider_label(value: str) -> str:
    """Human label for a Federated principal. Does not include our account ID."""
    lowered = value.lower()
    if GITHUB_OIDC_HOST in lowered:
        return "GitHub Actions OIDC"
    if any(marker in lowered for marker in GITLAB_OIDC_MARKERS):
        return "GitLab OIDC"
    if "cognito-identity" in lowered:
        return "Amazon Cognito identity pool"
    if ":saml-provider/" in lowered:
        return f"SAML IdP: {value.rsplit('/', 1)[-1]}"
    if ":oidc-provider/" in lowered:
        host = value.split(":oidc-provider/", 1)[-1]
        return f"OIDC: {host}"
    return f"Federated: {value}"


def flatten_condition_keys(condition: dict[str, Any] | None) -> set[str]:
    """Lowercased condition keys from nested IAM or flat Access Analyzer maps."""
    keys: set[str] = set()
    if not condition or not isinstance(condition, dict):
        return keys
    for operator, values in condition.items():
        if isinstance(values, dict):
            for inner_key in values:
                if isinstance(inner_key, str):
                    keys.add(inner_key.lower())
        elif isinstance(operator, str):
            # Access Analyzer flattens to {condition_key: value}.
            keys.add(operator.lower())
    return keys


_PRINCIPAL_BINDING_CONDITION_KEYS = frozenset(
    {
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:principalorgid",
        "aws:principalaccount",
        "aws:sourceowner",
        "aws:principalarn",
        "aws:principalorgpaths",
        "aws:sourceorgid",
        "kms:calleraccount",
    }
)


def condition_binds_principal(condition: dict[str, Any] | None) -> bool:
    """True when a Condition names who may use a Principal:* (not the public)."""
    keys = flatten_condition_keys(condition)
    return any(
        k in _PRINCIPAL_BINDING_CONDITION_KEYS or k.split(":")[-1] in {
            "sourceaccount",
            "sourcearn",
            "principalorgid",
            "principalaccount",
            "sourceowner",
            "principalarn",
            "principalorgpaths",
            "sourceorgid",
            "calleraccount",
        }
        for k in keys
    )


def _condition_values_for_key(condition: dict[str, Any] | None, wanted: str) -> list[str]:
    if not condition or not isinstance(condition, dict):
        return []
    wanted = wanted.lower()
    out: list[str] = []
    for operator, values in condition.items():
        if isinstance(values, dict):
            for inner_key, inner_val in values.items():
                if isinstance(inner_key, str) and inner_key.lower() == wanted:
                    if isinstance(inner_val, list):
                        out.extend(str(v) for v in inner_val)
                    elif inner_val is not None:
                        out.append(str(inner_val))
        elif isinstance(operator, str) and operator.lower() == wanted:
            if isinstance(values, list):
                out.extend(str(v) for v in values)
            elif values is not None:
                out.append(str(values))
    return out


def source_account_from_condition(condition: dict[str, Any] | None) -> str | None:
    """12-digit account from SourceAccount / PrincipalAccount / SourceArn, if any."""
    for key in (
        "aws:SourceAccount",
        "aws:PrincipalAccount",
        "kms:CallerAccount",
        "aws:SourceOwner",
    ):
        for raw in _condition_values_for_key(condition, key):
            value = raw.strip()
            if ACCOUNT_ID_PATTERN.match(value):
                return value
    for raw in _condition_values_for_key(condition, "aws:SourceArn"):
        extracted = extract_account_id_from_iam_value(raw.strip())
        if extracted:
            return extracted
    return None


def org_id_from_condition(condition: dict[str, Any] | None) -> str | None:
    """Organization ID from PrincipalOrgID / SourceOrgID when no account is named."""
    for key in ("aws:PrincipalOrgID", "aws:SourceOrgID"):
        for raw in _condition_values_for_key(condition, key):
            value = raw.strip()
            if value.startswith("o-") and len(value) >= 4:
                return value
    return None


def statement_has_external_id(condition: dict[str, Any] | None) -> bool:
    return any(k == "sts:externalid" for k in flatten_condition_keys(condition))


ORG_BOOTSTRAP_ROLE_NAMES = frozenset(
    {
        "OrganizationAccountAccessRole",
        "AWSControlTowerExecution",
        "AWSControlTowerAdmin",
    }
)


def role_name_from_resource(resource: str) -> str:
    if not resource:
        return ""
    return resource.rsplit("/", 1)[-1]


def is_org_bootstrap_role(resource: str) -> bool:
    """AWS-created org/StackSets roles are not confused-deputy leftovers."""
    name = role_name_from_resource(resource)
    if name in ORG_BOOTSTRAP_ROLE_NAMES:
        return True
    return name.startswith("stacksets-exec-")


def should_flag_missing_external_id(
    *,
    resource_type: str,
    mechanism: str,
    parsed: dict[str, Any],
    classification: str,
    resource: str,
    condition: dict[str, Any] | None,
) -> bool:
    """Confused-deputy leftover: untrusted cross-account role trusts without ExternalId.

    Trusted (org/YAML/CloudFront) and AWS org bootstrap roles are not flagged.
    Vendors still are — that is the Datadog-shaped case.
    """
    if resource_type != "AWS::IAM::Role":
        return False
    if mechanism not in ("trust_policy", "access_analyzer"):
        return False
    if parsed.get("kind") != "aws_account" or parsed.get("is_public"):
        return False
    if classification == "trusted":
        return False
    if is_org_bootstrap_role(resource):
        return False
    return not statement_has_external_id(condition)


def oidc_condition_gaps(federated_value: str, condition: dict[str, Any] | None) -> list[str]:
    """Return missing OIDC condition names for GitHub/GitLab trusts.

    GitHub: both ``aud`` and ``sub`` (docs: audience + repo subject).
    GitLab: ``sub`` (project path). Unknown OIDC issuers are not flagged.
    """
    keys = flatten_condition_keys(condition)
    lowered = federated_value.lower()
    gaps: list[str] = []
    if GITHUB_OIDC_HOST in lowered:
        if not any(k.endswith(":aud") for k in keys):
            gaps.append(f"{GITHUB_OIDC_HOST}:aud")
        if not any(k.endswith(":sub") for k in keys):
            gaps.append(f"{GITHUB_OIDC_HOST}:sub")
        return gaps
    if any(marker in lowered for marker in GITLAB_OIDC_MARKERS):
        if not any(k.endswith(":sub") for k in keys):
            gaps.append("oidc:sub")
        return gaps
    return gaps


def federated_raw_from_grant(grant: dict[str, Any]) -> str:
    """Federated issuer ARN/URL stored on a grant row."""
    praw = grant.get("principal_raw") or {}
    if isinstance(praw, dict):
        for key in ("Federated", "federated"):
            if praw.get(key):
                return str(praw[key])
        values = [v for v in praw.values() if v]
        if values:
            return str(values[0])
    return str(grant.get("principal") or "")


def matching_trust_condition(
    policy_document: dict[str, Any] | None,
    *,
    principal_kind: str,
    principal_raw: str,
    principal_account_id: str | None,
) -> dict[str, Any] | None:
    """Condition on the Allow statement that matches this principal, if found."""
    fallback: dict[str, Any] | None = None
    for stmt, ptype, value in iter_allow_principals(policy_document):
        cond = stmt.get("Condition") if isinstance(stmt.get("Condition"), dict) else {}
        if not isinstance(cond, dict):
            cond = {}
        if principal_kind == "federated" and ptype == "Federated":
            if principal_raw and str(value) == principal_raw:
                return cond
            if fallback is None:
                fallback = cond
        elif principal_kind == "aws_account" and ptype == "AWS":
            extracted = extract_account_id_from_iam_value(str(value))
            if principal_account_id and extracted == principal_account_id:
                return cond
            if principal_raw and str(value) == principal_raw:
                return cond
    return fallback


def apply_live_trust_conditions(
    grant: dict[str, Any],
    policy_document: dict[str, Any] | None,
) -> bool:
    """Recompute OIDC/ExternalId flags from a live AssumeRole policy.

    Access Analyzer findings often omit Condition. Empty AA condition is not
    proof the role is missing ``sub``/``aud`` or ExternalId.
    """
    kind = grant.get("principal_kind") or ""
    raw = federated_raw_from_grant(grant)
    cond = matching_trust_condition(
        policy_document,
        principal_kind=kind,
        principal_raw=raw,
        principal_account_id=grant.get("principal_account_id"),
    )
    if cond is None:
        return False
    grant["condition"] = cond
    grant["condition_source"] = "iam_get_role"
    if kind == "federated":
        gaps = oidc_condition_gaps(raw, cond)
        grant["oidc_gaps"] = gaps
        grant["missing_oidc_subject"] = bool(gaps)
    grant["missing_external_id"] = should_flag_missing_external_id(
        resource_type=grant.get("resource_type") or "",
        mechanism=grant.get("mechanism") or "access_analyzer",
        parsed={
            "kind": kind,
            "is_public": grant.get("is_public"),
        },
        classification=grant.get("classification") or "unknown",
        resource=grant.get("resource") or "",
        condition=cond,
    )
    return True


def clear_unproven_aa_condition_flags(grant: dict[str, Any]) -> None:
    """Do not report leftover flags when AA omitted conditions and we cannot read the role."""
    grant["missing_oidc_subject"] = False
    grant["oidc_gaps"] = []
    grant["missing_external_id"] = False
    grant["condition_source"] = "access_analyzer_omitted"


def choose_external_analyzer(
    candidates: list[dict[str, Any]],
    scope: str,
) -> dict[str, Any] | None:
    """Pick one analyzer for a region.

    ``auto`` prefers ACCOUNT so the default inventory is this account, not the
    whole organization zone of trust. ORGANIZATION is used only when no ACCOUNT
    analyzer exists in that region, or when scope is ``organization``.
    """
    if not candidates:
        return None
    if scope == "auto":
        acct = next((c for c in candidates if c.get("type") == "ACCOUNT"), None)
        if acct is not None:
            return acct
        org = next((c for c in candidates if c.get("type") == "ORGANIZATION"), None)
        return org if org is not None else candidates[0]
    return candidates[0]


def report_scope_label(requested_scope: str) -> str:
    """Report filename/grouping scope. Org slug only when the operator asked."""
    return "organization" if requested_scope == "organization" else "account"


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RESOURCE_TYPES_NAME_IS_ENOUGH = frozenset({"IAM Role", "IAM User", "S3 Bucket"})


def short_resource_name(arn_or_name: str, resource_type: str = "") -> str:
    """Last path or ARN segment — too lossy alone for UUIDs and SNS names like ``1``."""
    if not arn_or_name:
        return ""
    if resource_type == "AWS::Lambda::LayerVersion" and ":layer:" in arn_or_name:
        return arn_or_name.split(":layer:", 1)[-1]
    if "/" in arn_or_name:
        return arn_or_name.split("/")[-1]
    if ":" in arn_or_name:
        return arn_or_name.split(":")[-1]
    return arn_or_name


def compact_aws_resource_type(resource_type: str) -> str:
    if not resource_type:
        return ""
    body = resource_type.replace("AWS::", "")
    parts = body.split("::")
    if len(parts) == 2:
        return f"{parts[0]} {parts[1]}"
    return body.replace("::", " ")


def is_opaque_resource_name(name: str) -> bool:
    if not name:
        return True
    if _UUID_RE.fullmatch(name):
        return True
    if name.isdigit() and len(name) <= 8:
        return True
    return len(name) <= 2


def grant_resource_label(grant: dict[str, Any]) -> str:
    """Inventory label: resource name plus type when the name alone is unusable."""
    arn = grant.get("resource") or ""
    rtype = compact_aws_resource_type(grant.get("resource_type") or "")
    name = short_resource_name(arn, grant.get("resource_type") or "")
    if not name:
        return rtype or "—"
    needs_type = rtype and (
        is_opaque_resource_name(name) or rtype not in _RESOURCE_TYPES_NAME_IS_ENOUGH
    )
    if needs_type:
        return f"{name} ({rtype})"
    return name


def access_analyzer_grant_dedupe_key(grant: dict[str, Any]) -> tuple[Any, ...]:
    """Identity of one AA finding for cross-region / mixed-analyzer dedupe."""
    return (
        grant.get("resource") or "",
        grant.get("principal_kind") or "",
        grant.get("principal_account_id") or "",
        grant.get("principal_label") or grant.get("principal") or "",
        bool(grant.get("is_public")),
    )


def dedupe_access_analyzer_grants(
    grants: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """IAM roles are global; ACCOUNT + ORGANIZATION analyzers often emit the same finding.

    Prefers ACCOUNT-analyzer rows when both exist.
    """
    others = [g for g in grants if g.get("mechanism") != "access_analyzer"]
    aa = [g for g in grants if g.get("mechanism") == "access_analyzer"]
    aa.sort(key=lambda g: 0 if g.get("analyzer_type") == "ACCOUNT" else 1)
    seen: set[tuple[Any, ...]] = set()
    kept: list[dict[str, Any]] = []
    dropped = 0
    for grant in aa:
        key = access_analyzer_grant_dedupe_key(grant)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(grant)
    return others + kept, dropped


def iter_statements(policy_document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not policy_document:
        return []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if not isinstance(statements, list):
        return []
    return [s for s in statements if isinstance(s, dict)]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def iter_allow_principals(
    policy_document: dict[str, Any] | None,
) -> list[tuple[dict[str, Any], str, str]]:
    """Yield (statement, principal_type, principal_value) for Allow grants.

    ``principal_type`` is AWS, Federated, CanonicalUser, or Wildcard.
    Service principals are omitted. Deny statements are omitted.
    """
    out: list[tuple[dict[str, Any], str, str]] = []
    for statement in iter_statements(policy_document):
        if statement.get("Effect", "Allow") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            out.append((statement, "Wildcard", "*"))
            continue
        if not isinstance(principal, dict):
            continue
        for ptype, raw in principal.items():
            if ptype == "Service":
                continue
            if ptype == "CanonicalUser":
                for item in _as_list(raw):
                    if isinstance(item, str) and item:
                        out.append((statement, "CanonicalUser", item))
                continue
            for item in _as_list(raw):
                if not isinstance(item, str) or not item:
                    continue
                if ptype == "AWS" and is_aws_service_principal(item):
                    continue
                if ptype == "AWS" and item == "*":
                    out.append((statement, "Wildcard", "*"))
                else:
                    out.append((statement, ptype, item))
    return out


def parse_principal_value(
    principal_type: str,
    value: str,
    *,
    our_organization_id: str | None = None,
) -> dict[str, Any]:
    """Normalize one principal into kind / account / org / public / label.

    Never treats the account ID inside a Federated or Organizations ARN as
    the external party.
    """
    parsed: dict[str, Any] = {
        "kind": "unknown",
        "account_id": None,
        "organization_id": None,
        "is_public": False,
        "label": value,
        "raw": value,
        "is_our_organization": False,
    }
    if principal_type in ("Wildcard",) or value == "*":
        parsed.update(kind="public", is_public=True, label="Everyone (*)")
        return parsed
    if principal_type == "CanonicalUser":
        parsed.update(kind="canonical_user", label=f"Canonical user {value[:12]}…")
        return parsed
    if principal_type == "Federated":
        parsed.update(
            kind="federated",
            label=federated_provider_label(value),
        )
        return parsed

    cf_match = CLOUDFRONT_IAM_USER_RE.match(value)
    if cf_match:
        parsed.update(
            kind="cloudfront",
            label=cloudfront_principal_label(cf_match.group(1)),
        )
        return parsed

    org_match = ORGANIZATIONS_ARN_RE.match(value)
    if org_match:
        org_or_ou, rest = org_match.group(2), org_match.group(3)
        # organization/o-xxxx  or  ou/o-xxxx/ou-yyyy
        org_id = rest if org_or_ou == "organization" else rest.split("/", 1)[0]
        is_ours = bool(our_organization_id and org_id == our_organization_id)
        parsed.update(
            kind="ou" if org_or_ou == "ou" else "organization",
            organization_id=org_id,
            is_our_organization=is_ours,
            label=(
                f"OU {rest.rsplit('/', 1)[-1]}"
                if org_or_ou == "ou"
                else f"AWS Organization {org_id}"
            ),
        )
        return parsed

    if value.lower() in ("all", "group=all"):
        parsed.update(kind="public", is_public=True, label="Everyone (all)")
        return parsed

    account_id = extract_account_id_from_iam_value(value)
    if account_id:
        parsed.update(kind="aws_account", account_id=account_id, label=account_id)
        return parsed

    parsed.update(kind="unknown", label=value)
    return parsed


def classify_parsed_principal(
    parsed: dict[str, Any],
    *,
    trusted_accounts: dict[str, dict[str, Any]],
    account_to_vendor: dict[str, dict[str, Any]],
    current_account_id: str | None,
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    """Return (classification, vendor_info, trusted_info).

    Same-account principals should be filtered before calling; if they slip
    through they classify as trusted.
    """
    if parsed.get("is_public"):
        return "public", None, None
    if parsed.get("kind") == "federated":
        return "federated", None, None
    if parsed.get("kind") == "cloudfront":
        return "trusted", None, {
            "name": "Amazon CloudFront",
            "source": "aws_cloudfront",
        }
    if parsed.get("kind") in ("organization", "ou"):
        if parsed.get("is_our_organization"):
            return "trusted", None, {
                "name": "This AWS Organization",
                "source": "aws_org",
            }
        return "unknown", None, None
    if parsed.get("kind") == "canonical_user":
        return "unknown", None, None
    if parsed.get("kind") == "credential":
        return "unknown", None, None

    account_id = parsed.get("account_id")
    if account_id and current_account_id and account_id == current_account_id:
        return "trusted", None, {
            "name": "This account",
            "source": "self",
        }
    if account_id and account_id in trusted_accounts:
        return "trusted", None, trusted_accounts[account_id]
    if account_id and account_id in account_to_vendor:
        return "vendor", account_to_vendor[account_id], None
    return "unknown", None, None


def is_same_account_principal(
    parsed: dict[str, Any], current_account_id: str | None
) -> bool:
    if not current_account_id:
        return False
    if parsed.get("is_public") or parsed.get("kind") in (
        "federated",
        "cloudfront",
        "organization",
        "ou",
        "canonical_user",
        "credential",
    ):
        return False
    return parsed.get("account_id") == current_account_id


def empty_grant(**overrides: Any) -> dict[str, Any]:
    grant: dict[str, Any] = {
        "resource": "",
        "resource_type": "",
        "principal": "",
        "principal_kind": "unknown",
        "principal_account_id": None,
        "principal_label": "",
        "principal_raw": {},
        "mechanism": "",
        "region": "",
        "actions": [],
        "condition": {},
        "classification": "unknown",
        "vendor": None,
        "trusted": None,
        "is_public": False,
        "missing_external_id": False,
        "missing_oidc_subject": False,
        "oidc_gaps": [],
        "never_expires": False,
        "credential_status": "",
        "owner_account": "",
        "owner_label": "",
        "analyzer_type": "",
        "analyzed_at": "",
        "id": "",
        "organization_id": None,
        "name_source": "",
        "blocked_by_bpa": False,
        "effective_public": None,
    }
    grant.update(overrides)
    return grant


def lookup_name_source(
    *,
    classification: str,
    vendor: dict[str, Any] | None,
    trusted: dict[str, Any] | None,
    parsed: dict[str, Any],
) -> str:
    """Directory that produced the principal's display name."""
    if parsed.get("is_public"):
        return "public"
    if parsed.get("kind") == "federated":
        return "federated"
    if trusted:
        return str(trusted.get("source") or "trusted")
    if vendor:
        if vendor.get("type") == "aws-support":
            return "aws_builtin"
        return "fwd:cloudsec"
    if parsed.get("account_id") or parsed.get("organization_id"):
        return "not_in_dataset"
    return "unresolved"


def apply_s3_effective_public(
    grant: dict[str, Any],
    is_effectively_public: bool | None,
) -> dict[str, Any]:
    """If GetBucketPolicyStatus says the bucket is not public, this is not current access.

    ``None`` means the API failed — keep the Allow-* row as public (conservative).
    """
    if grant.get("resource_type") != "AWS::S3::Bucket":
        return grant
    if not grant.get("is_public"):
        return grant
    grant["effective_public"] = is_effectively_public
    if is_effectively_public is False:
        grant["is_public"] = False
        grant["blocked_by_bpa"] = True
        grant["classification"] = "blocked_public"
        grant["name_source"] = "blocked_by_bpa"
    return grant


def _party_sort_key(party: dict[str, Any]) -> tuple[int, int, str]:
    rank = _PARTY_CLASS_RANK.get(party["classification"], 9)
    name = (party.get("name") or "").lower()
    federated_rank = 1
    if party["classification"] == "federated":
        if "github" in name or "gitlab" in name:
            federated_rank = 0
        elif "cognito" in name:
            federated_rank = 2
    return (rank, federated_rank, party.get("name") or "")


def party_identity_key(grant: dict[str, Any]) -> str:
    """Group key: one AWS account, one federated issuer, or public."""
    if grant.get("blocked_by_bpa") or grant.get("classification") == "blocked_public":
        return f"bpa:{grant.get('resource') or ''}"
    if grant.get("is_public") or grant.get("classification") == "public":
        return "public:*"
    account_id = grant.get("principal_account_id")
    if account_id:
        return f"account:{account_id}"
    kind = grant.get("principal_kind") or ""
    label = grant.get("principal_label") or grant.get("principal") or ""
    if kind == "federated":
        return f"federated:{label}"
    if kind == "cloudfront":
        return "cloudfront:aws"
    org_id = grant.get("organization_id")
    if org_id:
        return f"org:{org_id}"
    return f"other:{label}"


def parties_from_grants(grants: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse grant rows into one party per external principal.

    Blocked-by-BPA rows are omitted — they are not current access.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for grant in grants:
        if grant.get("blocked_by_bpa") or grant.get("classification") == "blocked_public":
            continue
        grouped.setdefault(party_identity_key(grant), []).append(grant)

    parties: list[dict[str, Any]] = []
    for key, items in grouped.items():
        first = items[0]
        mechanisms = list(
            dict.fromkeys(
                MECHANISM_LABELS.get(g.get("mechanism") or "", g.get("mechanism") or "")
                for g in items
            )
        )
        name = first.get("principal_label") or first.get("principal") or ""
        if first.get("principal_kind") == "cloudfront":
            trusted = first.get("trusted") or {}
            name = trusted.get("name") or "Amazon CloudFront"
        parties.append(
            {
                "key": key,
                "name": name,
                "account_id": first.get("principal_account_id"),
                "name_source": first.get("name_source") or "",
                "name_source_label": NAME_SOURCE_LABELS.get(
                    first.get("name_source") or "",
                    first.get("name_source") or "",
                ),
                "classification": first.get("classification") or "unknown",
                "grant_count": len(items),
                "mechanisms": mechanisms,
                "resources": [g.get("resource") or "" for g in items],
                "grants": items,
            }
        )
    parties.sort(key=_party_sort_key)
    return parties


def index_known_accounts(vendors_data: Any) -> dict[str, dict[str, Any]]:
    """Index fwd:cloudsec-shaped YAML (list of {name, accounts, ...}) by account ID."""
    account_to_vendor: dict[str, dict[str, Any]] = {}
    if not isinstance(vendors_data, list):
        return account_to_vendor
    for vendor in vendors_data:
        if not isinstance(vendor, dict):
            continue
        for raw_id in vendor.get("accounts") or []:
            account_id = str(raw_id).strip()
            if len(account_id) != 12 or not account_id.isdigit():
                continue
            account_to_vendor[account_id] = {
                "name": vendor.get("name", "Unknown"),
                "type": vendor.get("type", "third-party"),
                "source": vendor.get("source", []),
            }
    return account_to_vendor


def grant_from_parsed_principal(
    parsed: dict[str, Any],
    *,
    statement: dict[str, Any] | None,
    resource: str,
    resource_type: str,
    mechanism: str,
    trusted_accounts: dict[str, dict[str, Any]],
    account_to_vendor: dict[str, dict[str, Any]],
    current_account_id: str | None,
    region: str = "",
    owner_account: str = "",
    owner_label: str = "",
    actions: list[str] | None = None,
    our_organization_id: str | None = None,
) -> dict[str, Any] | None:
    """Build one grant row, or None if this principal is the current account."""
    condition = (statement or {}).get("Condition") or {}
    if not isinstance(condition, dict):
        condition = {}
    if (
        parsed.get("is_public")
        and condition_binds_principal(condition)
        and mechanism != "access_analyzer"
    ):
        source_acct = source_account_from_condition(condition)
        if source_acct:
            parsed = parse_principal_value(
                "AWS", source_acct, our_organization_id=our_organization_id
            )
        else:
            org_id = org_id_from_condition(condition)
            if not org_id:
                # Principal:* + SourceArn without an account ID is not public
                # access; it is a service notification pattern we cannot name.
                return None
            parsed = parse_principal_value(
                "AWS",
                f"arn:aws:organizations::000000000000:organization/{org_id}",
                our_organization_id=our_organization_id,
            )
    if is_same_account_principal(parsed, current_account_id):
        return None
    classification, vendor, trusted = classify_parsed_principal(
        parsed,
        trusted_accounts=trusted_accounts,
        account_to_vendor=account_to_vendor,
        current_account_id=current_account_id,
    )
    missing_external_id = should_flag_missing_external_id(
        resource_type=resource_type,
        mechanism=mechanism,
        parsed=parsed,
        classification=classification,
        resource=resource,
        condition=condition if isinstance(condition, dict) else {},
    )
    oidc_gaps: list[str] = []
    if parsed.get("kind") == "federated":
        oidc_gaps = oidc_condition_gaps(parsed.get("raw") or "", condition)

    name_source = lookup_name_source(
        classification=classification,
        vendor=vendor,
        trusted=trusted,
        parsed=parsed,
    )
    principal_label = parsed["label"]
    if parsed.get("account_id") and classification == "vendor" and vendor:
        principal_label = f"{parsed['account_id']} ({vendor.get('name')})"
    elif parsed.get("account_id") and classification == "trusted" and trusted:
        principal_label = f"{parsed['account_id']} ({trusted.get('name')})"
    elif parsed.get("account_id") and classification == "unknown":
        principal_label = f"{parsed['account_id']} (not in known_aws_accounts)"
    elif parsed.get("kind") in ("organization", "ou") and classification == "trusted" and trusted:
        principal_label = trusted.get("name") or parsed["label"]
    elif parsed.get("kind") in ("organization", "ou") and classification == "unknown":
        principal_label = f"{parsed['label']} (not in known_aws_accounts)"

    return empty_grant(
        resource=resource,
        resource_type=resource_type,
        principal=parsed.get("account_id") or parsed["label"],
        principal_kind=parsed["kind"],
        principal_account_id=parsed.get("account_id"),
        principal_label=principal_label,
        principal_raw={parsed.get("kind", "unknown"): parsed.get("raw")},
        mechanism=mechanism,
        region=region,
        actions=list(actions or []),
        condition=condition if isinstance(condition, dict) else {},
        classification=classification,
        vendor=vendor,
        trusted=trusted,
        name_source=name_source,
        is_public=bool(parsed.get("is_public")),
        missing_external_id=missing_external_id,
        missing_oidc_subject=bool(oidc_gaps),
        oidc_gaps=oidc_gaps,
        owner_account=owner_account or (current_account_id or ""),
        owner_label=owner_label,
        organization_id=parsed.get("organization_id"),
    )


def grants_from_policy_document(
    policy_document: dict[str, Any] | None,
    *,
    resource: str,
    resource_type: str,
    mechanism: str,
    trusted_accounts: dict[str, dict[str, Any]],
    account_to_vendor: dict[str, dict[str, Any]],
    current_account_id: str | None,
    region: str = "",
    owner_account: str = "",
    owner_label: str = "",
    our_organization_id: str | None = None,
    default_actions: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Expand a resource/trust policy into one grant per Allow principal."""
    grants: list[dict[str, Any]] = []
    for statement, ptype, value in iter_allow_principals(policy_document):
        parsed = parse_principal_value(
            ptype, value, our_organization_id=our_organization_id
        )
        actions = default_actions
        stmt_action = statement.get("Action")
        if stmt_action:
            actions = [a for a in _as_list(stmt_action) if isinstance(a, str)]
        grant = grant_from_parsed_principal(
            parsed,
            statement=statement,
            resource=resource,
            resource_type=resource_type,
            mechanism=mechanism,
            trusted_accounts=trusted_accounts,
            account_to_vendor=account_to_vendor,
            current_account_id=current_account_id,
            region=region,
            owner_account=owner_account,
            owner_label=owner_label,
            actions=actions,
            our_organization_id=our_organization_id,
        )
        if grant:
            grants.append(grant)
    return grants


def actions_from_ram_permission(permission_doc: Any) -> list[str]:
    """Pull Action lists out of a RAM managed-permission document."""
    if permission_doc is None:
        return []
    if isinstance(permission_doc, str):
        try:
            permission_doc = json.loads(permission_doc)
        except json.JSONDecodeError:
            return []
    actions: list[str] = []
    if isinstance(permission_doc, dict):
        if "Action" in permission_doc:
            actions.extend(
                a for a in _as_list(permission_doc["Action"]) if isinstance(a, str)
            )
        for statement in iter_statements(permission_doc):
            actions.extend(
                a for a in _as_list(statement.get("Action")) if isinstance(a, str)
            )
    return list(dict.fromkeys(actions))


def loads_policy_document(raw: Any) -> dict[str, Any] | None:
    """Parse a resource-policy payload that APIs return as dict or JSON string."""
    if not raw:
        return None
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if isinstance(raw, dict):
        return raw
    return None


def party_totals(parties: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count external parties by classification (not grant rows)."""
    totals = {
        "parties": 0,
        "unknown": 0,
        "public": 0,
        "vendor": 0,
        "federated": 0,
        "trusted": 0,
    }
    for party in parties:
        totals["parties"] += 1
        classification = party.get("classification") or "unknown"
        if classification in totals:
            totals[classification] += 1
        else:
            totals["unknown"] += 1
    return totals


def totals_from_grants(grants: Iterable[dict[str, Any]]) -> dict[str, int]:
    totals = {
        "trusted": 0,
        "vendors": 0,
        "unknown": 0,
        "public": 0,
        "federated": 0,
        "missing_external_id": 0,
        "missing_oidc_subject": 0,
        "never_expires": 0,
        "blocked_public": 0,
        "findings": 0,
    }
    for grant in grants:
        totals["findings"] += 1
        classification = grant.get("classification")
        if grant.get("is_public") or classification == "public":
            totals["public"] += 1
        elif classification == "blocked_public":
            totals["blocked_public"] += 1
        elif classification == "trusted":
            totals["trusted"] += 1
        elif classification == "vendor":
            totals["vendors"] += 1
        elif classification == "federated":
            totals["federated"] += 1
        else:
            totals["unknown"] += 1
        if grant.get("missing_external_id"):
            totals["missing_external_id"] += 1
        if grant.get("missing_oidc_subject"):
            totals["missing_oidc_subject"] += 1
        if grant.get("never_expires") and grant.get("credential_status", "Active") != "Inactive":
            totals["never_expires"] += 1
    return totals


def build_coverage(
    *,
    backend: str,
    scanned: list[dict[str, str]],
    skipped: list[dict[str, str]] | None = None,
    regions: list[str] | None = None,
    all_regions: bool = False,
    analyzer_notes: list[str] | None = None,
) -> dict[str, Any]:
    """Coverage banner payload for reports.

    ``scanned`` / ``skipped`` items are ``{"surface": ..., "detail": ...}``.
    """
    not_scanned = list(skipped or [])
    for surface, reason in OUT_OF_SCOPE_SURFACES:
        not_scanned.append({"surface": surface, "detail": reason})
    if backend == "policy_scanner":
        not_scanned.insert(
            0,
            {
                "surface": "S3 ACLs, EFS file systems, RDS snapshots",
                "detail": (
                    "Key/topic/queue/function/layer/secret/ECR policies and KMS "
                    "ListGrants are scanned. Remaining AA types need Access Analyzer."
                ),
            },
        )
        not_scanned.insert(
            1,
            {
                "surface": "Deny statements and most conditions",
                "detail": (
                    "Policy scanner is Allow-principal matching. Public S3 rows "
                    "are checked with GetBucketPolicyStatus (Block Public Access). "
                    "Principal:* with aws:SourceAccount/SourceArn/PrincipalOrgID "
                    "is named as that account or organization, not public."
                ),
            },
        )
    elif backend == "access_analyzer":
        not_scanned.insert(
            0,
            {
                "surface": f"IAM Access Analyzer ceiling ({len(AA_SUPPORTED_TYPES)} resource types)",
                "detail": (
                    "AA does not cover RAM shares, AMI launch permissions, "
                    "SSM document shares, EventBridge/Glue/OpenSearch resource "
                    "policies, Lambda aliases/versions, or service principals"
                ),
            },
        )
        not_scanned.insert(
            1,
            {
                "surface": "Analyzer scan completeness",
                "detail": (
                    "Analyzer status ACTIVE is not 'scan finished'. First scan "
                    "can take ~20 minutes; findings lag policy changes by up to 30 minutes"
                ),
            },
        )
    if regions and not all_regions:
        not_scanned.insert(
            0,
            {
                "surface": "Regional collectors outside " + ", ".join(regions),
                "detail": "Pass --all-regions (or a wider --regions list) to cover every enabled region",
            },
        )
    return {
        "backend": backend,
        "scanned": scanned,
        "not_scanned": not_scanned,
        "regions": list(regions or []),
        "all_regions": all_regions,
        "analyzer_notes": list(analyzer_notes or []),
        "aa_supported_types": list(AA_SUPPORTED_TYPES) if backend == "access_analyzer" else [],
    }
