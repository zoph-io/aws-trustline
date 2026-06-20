"""AWS Lambda handler that runs AWS Trustline on a schedule.

Drives the Access Analyzer backend directly via the trustline module so we can
inspect totals after the scan (for SNS alerts) without parsing console output.
The generated HTML report is uploaded to S3 under a date-partitioned key and
an SNS notification is published when any finding warrants attention.

Expected environment variables:
    REPORT_BUCKET     S3 bucket for HTML reports (required)
    SCOPE             auto | account | organization (default: auto)
    REGIONS           comma list, or 'all' for ec2:DescribeRegions enumeration
                      (default: 'all')
    ALERT_TOPIC_ARN   optional SNS topic ARN for alerts; empty disables SNS
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3

import trustline

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):  # noqa: ARG001
    scope = os.environ.get("SCOPE", "auto")
    regions_setting = os.environ.get("REGIONS", "all").strip()
    bucket = os.environ["REPORT_BUCKET"]
    alert_topic = (os.environ.get("ALERT_TOPIC_ARN") or "").strip() or None

    logger.info(
        "Starting Trustline scan: scope=%s regions=%s bucket=%s alert_topic=%s",
        scope, regions_setting, bucket, bool(alert_topic),
    )

    session = boto3.Session()

    account_to_vendor = trustline.fetch_reference_data()
    logger.info("Loaded %d known vendor accounts", len(account_to_vendor))

    # No YAML trusted-accounts file is shipped in the Lambda package; pass a
    # path that does not exist so fetch_trusted_accounts falls back to
    # AWS Organizations only.
    trusted_accounts, org_error = trustline.fetch_trusted_accounts(
        session, trusted_accounts_file="/tmp/trustline-no-such-yaml.yaml"
    )
    org_accounts = {
        acct_id: meta
        for acct_id, meta in trusted_accounts.items()
        if meta.get("source") == "aws_org"
    }
    account_aliases = trustline.get_account_aliases(session)

    # resolve_regions is driven off of argparse-like attributes; build a
    # Namespace that mirrors the CLI surface so we can reuse it as-is.
    args = argparse.Namespace(
        regions=None if regions_setting in ("", "all") else regions_setting,
        all_regions=(regions_setting == "all"),
    )
    try:
        regions = trustline.resolve_regions(session, args)
    except (ValueError, RuntimeError) as e:
        logger.error("Region resolution failed: %s", e)
        if alert_topic:
            _publish_alert(
                alert_topic,
                "Trustline: region resolution failed",
                f"Lambda could not resolve regions for the scan: {e}",
            )
        return _result("region-resolution-failed", error=str(e))

    logger.info("Discovering analyzers in %d region(s): %s", len(regions), regions)
    analyzers = trustline.find_external_analyzers(session, regions, scope)
    if not analyzers:
        msg = (
            f"No external Access Analyzer found in any of: "
            f"{', '.join(regions)} (scope: {scope}). "
            "Create one with `aws accessanalyzer create-analyzer "
            f"--analyzer-name trustline --type "
            f"{'ORGANIZATION' if scope == 'organization' else 'ACCOUNT'}`."
        )
        logger.error(msg)
        if alert_topic:
            _publish_alert(alert_topic, "Trustline: no analyzer found", msg)
        return _result("no-analyzer", scope=scope, regions=regions)

    for region, analyzer in analyzers.items():
        logger.info("Using %s analyzer in %s: %s",
                    analyzer["type"], region, analyzer["name"])

    report_data = trustline.collect_access_analyzer_findings(
        session=session,
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
        analyzers=analyzers,
    )

    effective_scope = scope
    if effective_scope == "auto":
        effective_scope = (
            "organization"
            if any(a["type"] == "ORGANIZATION" for a in analyzers.values())
            else "account"
        )

    output_dir = "/tmp/trustline-reports"
    os.makedirs(output_dir, exist_ok=True)
    report_path = trustline.generate_html_report_aa(
        report_data,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
        scope=effective_scope,
        output_dir=output_dir,
    )

    now = datetime.now(timezone.utc)
    key = (
        f"reports/{now.strftime('%Y/%m/%d')}/"
        f"{os.path.basename(report_path)}"
    )
    s3 = boto3.client("s3")
    s3.upload_file(
        report_path, bucket, key,
        ExtraArgs={
            "ContentType": "text/html; charset=utf-8",
            "CacheControl": "private, max-age=0, no-store",
        },
    )
    logger.info("Uploaded report to s3://%s/%s (%d bytes)",
                bucket, key, os.path.getsize(report_path))

    totals = report_data["totals"]

    if alert_topic and _should_alert(totals):
        _publish_findings_alert(
            alert_topic, totals, effective_scope, analyzers, bucket, key
        )

    return _result(
        "ok",
        scope=effective_scope,
        regions=list(analyzers.keys()),
        totals=totals,
        report_key=key,
        bucket=bucket,
        org_error=org_error,
    )


def _should_alert(totals: dict) -> bool:
    """Alert when any externally-attributable risk signal is non-zero."""
    return (
        totals.get("public", 0) > 0
        or totals.get("unknown", 0) > 0
        or totals.get("missing_external_id", 0) > 0
    )


def _publish_findings_alert(
    topic_arn: str,
    totals: dict,
    scope: str,
    analyzers: dict,
    bucket: str,
    key: str,
) -> None:
    subject = (
        f"Trustline alert: {totals['public']} public, "
        f"{totals['unknown']} unknown, "
        f"{totals['missing_external_id']} missing-ExternalId"
    )
    body = (
        f"AWS Trustline scheduled scan finished with findings that warrant review.\n\n"
        f"Scope: {scope}\n"
        f"Regions analyzed: {len(analyzers)} ({', '.join(sorted(analyzers))})\n"
        f"Owner accounts seen: {totals.get('owner_accounts', 0)}\n\n"
        f"Public findings (shared with the world): {totals.get('public', 0)}\n"
        f"Unknown external principal findings: {totals.get('unknown', 0)}\n"
        f"IAM roles missing ExternalId: {totals.get('missing_external_id', 0)}\n"
        f"Known-vendor findings: {totals.get('vendors', 0)}\n"
        f"Trusted findings: {totals.get('trusted', 0)}\n"
        f"Total findings: {totals.get('findings', 0)}\n\n"
        f"Full HTML report: s3://{bucket}/{key}\n"
    )
    _publish_alert(topic_arn, subject, body)


def _publish_alert(topic_arn: str, subject: str, body: str) -> None:
    boto3.client("sns").publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=body,
    )


def _result(status: str, **fields) -> dict:
    out = {"status": status, **fields}
    logger.info("Result: %s", json.dumps(out, default=str))
    return out


if __name__ == "__main__":
    # Local smoke entry: invoke with the same env vars the Lambda would see.
    print(json.dumps(lambda_handler({}, None), default=str, indent=2))
    sys.exit(0)
