# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Victor Grenu / zoph.io
"""AWS Lambda handler that runs AWS Trustline on a schedule.

Drives the Access Analyzer backend plus RAM / AMI / SSM / credential scanners
so we can inspect totals after the scan (for SNS alerts) without parsing
console output. The generated HTML report is uploaded to S3 under a
date-partitioned key and an SNS notification is published when any leftover
grant warrants attention.

Expected environment variables:
    REPORT_BUCKET       S3 bucket for HTML reports (required)
    SCOPE               auto | account | organization (default: auto)
    REGIONS             comma list, or 'all' for ec2:DescribeRegions enumeration
                        (default: 'all')
    ALERT_TOPIC_ARN     optional SNS topic ARN for alerts; empty disables SNS
    WAIT_FOR_ANALYZER   1/true to poll until AA finding counts stabilize
    WAIT_TIMEOUT        seconds for that wait (default: 300)
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
    our_organization_id = trustline.fetch_organization_id(session)

    wait_for_analyzer = os.environ.get("WAIT_FOR_ANALYZER", "").lower() in (
        "1",
        "true",
        "yes",
    )
    wait_timeout = int(os.environ.get("WAIT_TIMEOUT") or trustline.DEFAULT_WAIT_TIMEOUT)

    # resolve_regions / optional scanners are driven off argparse-like attributes.
    args = argparse.Namespace(
        regions=None if regions_setting in ("", "all") else regions_setting,
        all_regions=(regions_setting == "all"),
        skip_ram=False,
        skip_ami=False,
        skip_ssm=False,
        skip_credentials=False,
        wait_for_analyzer=wait_for_analyzer,
        wait_timeout=wait_timeout,
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

    wait_notes: list = []
    if wait_for_analyzer:
        wait_notes = trustline.wait_for_analyzer_findings(
            session, analyzers, timeout=wait_timeout
        )
        for note in wait_notes:
            logger.info("Analyzer wait: %s", note)

    report_data = trustline.collect_access_analyzer_findings(
        session=session,
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
        analyzers=analyzers,
        our_organization_id=our_organization_id,
    )

    current_account_id = next(iter(account_aliases), "")
    kwargs = trustline.grant_collect_context(
        account_to_vendor=account_to_vendor,
        trusted_accounts=trusted_accounts,
        current_account_id=current_account_id,
        our_organization_id=our_organization_id,
        account_aliases=account_aliases,
        org_accounts=org_accounts,
    )
    extra, scanned, skipped = trustline.collect_optional_scanners(
        session, args, regions, kwargs
    )
    grants = list(report_data.get("grants") or []) + extra
    report_data["grants"] = grants
    report_data["totals"] = trustline.totals_from_grants(grants)
    report_data["totals"]["regions"] = len(analyzers)
    report_data["totals"]["owner_accounts"] = len(report_data.get("owner_accounts") or [])
    report_data["coverage"] = trustline.build_coverage(
        backend="access_analyzer",
        scanned=(
            [{"surface": "IAM Access Analyzer external findings", "detail": ", ".join(analyzers)}]
            + scanned
        ),
        skipped=skipped,
        regions=regions,
        all_regions=bool(args.all_regions),
        analyzer_notes=wait_notes + list(report_data.get("analyzer_notes") or []),
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
    """Alert when any leftover external-access signal is non-zero."""
    return (
        totals.get("public", 0) > 0
        or totals.get("unknown", 0) > 0
        or totals.get("missing_external_id", 0) > 0
        or totals.get("missing_oidc_subject", 0) > 0
        or totals.get("never_expires", 0) > 0
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
        f"Trustline alert: {totals.get('public', 0)} public, "
        f"{totals.get('unknown', 0)} unknown, "
        f"{totals.get('missing_external_id', 0)} missing-ExternalId"
    )
    body = (
        f"AWS Trustline scheduled scan finished with findings that warrant review.\n\n"
        f"Scope: {scope}\n"
        f"Regions analyzed: {len(analyzers)} ({', '.join(sorted(analyzers))})\n"
        f"Owner accounts seen: {totals.get('owner_accounts', 0)}\n\n"
        f"Public grants: {totals.get('public', 0)}\n"
        f"Unknown principal grants: {totals.get('unknown', 0)}\n"
        f"Federated principals: {totals.get('federated', 0)}\n"
        f"IAM roles missing ExternalId: {totals.get('missing_external_id', 0)}\n"
        f"OIDC missing sub/aud: {totals.get('missing_oidc_subject', 0)}\n"
        f"Never-expiring service credentials: {totals.get('never_expires', 0)}\n"
        f"Known-vendor grants: {totals.get('vendors', 0)}\n"
        f"Trusted grants: {totals.get('trusted', 0)}\n"
        f"Total grants: {totals.get('findings', 0)}\n\n"
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
