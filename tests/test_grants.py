# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Victor Grenu / zoph.io
"""Unit tests for grant-row classification (no AWS calls)."""

from __future__ import annotations

import unittest

from grants import (
    actions_from_ram_permission,
    classify_parsed_principal,
    extract_account_id_from_iam_value,
    grants_from_policy_document,
    merge_builtin_vendors,
    oidc_condition_gaps,
    parse_principal_value,
    totals_from_grants,
)


GITHUB_OIDC_ARN = (
    "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
)
GITLAB_OIDC_ARN = "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
FOREIGN_ORG_ARN = "arn:aws:organizations::999999999999:organization/o-foreign"
OUR_ORG_ARN = "arn:aws:organizations::111122223333:organization/o-ours"
OUR_OU_ARN = "arn:aws:organizations::111122223333:ou/o-ours/ou-abcd1234"
CLOUDFRONT_OAI_ARN = (
    "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity EI92CX6OGEMUI"
)
CLOUDFRONT_OAC_ARN = (
    "arn:aws:iam::cloudfront:user/CloudFront Origin Access Control E1ABCDEF"
)


class ExtractAccountIdTests(unittest.TestCase):
    def test_raw_account_id(self):
        self.assertEqual(extract_account_id_from_iam_value("444455556666"), "444455556666")

    def test_iam_role_arn(self):
        self.assertEqual(
            extract_account_id_from_iam_value(
                "arn:aws:iam::444455556666:role/PartnerReader"
            ),
            "444455556666",
        )

    def test_oidc_provider_arn_is_not_the_external_party(self):
        self.assertIsNone(extract_account_id_from_iam_value(GITHUB_OIDC_ARN))

    def test_saml_provider_arn_is_not_the_external_party(self):
        self.assertIsNone(
            extract_account_id_from_iam_value(
                "arn:aws:iam::111122223333:saml-provider/Okta"
            )
        )

    def test_organizations_arn_is_not_the_management_account(self):
        self.assertIsNone(extract_account_id_from_iam_value(FOREIGN_ORG_ARN))
        self.assertIsNone(extract_account_id_from_iam_value(OUR_OU_ARN))

    def test_wildcard(self):
        self.assertIsNone(extract_account_id_from_iam_value("*"))

    def test_cloudfront_oai_is_not_an_account_id(self):
        self.assertIsNone(extract_account_id_from_iam_value(CLOUDFRONT_OAI_ARN))


class ParsePrincipalTests(unittest.TestCase):
    def test_public_wildcard(self):
        parsed = parse_principal_value("Wildcard", "*")
        self.assertTrue(parsed["is_public"])
        self.assertEqual(parsed["kind"], "public")

    def test_federated_github_label_has_no_account_id(self):
        parsed = parse_principal_value("Federated", GITHUB_OIDC_ARN)
        self.assertEqual(parsed["kind"], "federated")
        self.assertIsNone(parsed["account_id"])
        self.assertEqual(parsed["label"], "GitHub Actions OIDC")

    def test_foreign_org_arn_is_not_our_org(self):
        parsed = parse_principal_value(
            "AWS", FOREIGN_ORG_ARN, our_organization_id="o-ours"
        )
        self.assertEqual(parsed["kind"], "organization")
        self.assertFalse(parsed["is_our_organization"])
        self.assertIsNone(parsed["account_id"])

    def test_our_org_arn_is_flagged(self):
        parsed = parse_principal_value(
            "AWS", OUR_ORG_ARN, our_organization_id="o-ours"
        )
        self.assertTrue(parsed["is_our_organization"])

    def test_our_ou_arn_uses_org_id_not_management_account(self):
        parsed = parse_principal_value(
            "AWS", OUR_OU_ARN, our_organization_id="o-ours"
        )
        self.assertEqual(parsed["kind"], "ou")
        self.assertEqual(parsed["organization_id"], "o-ours")
        self.assertTrue(parsed["is_our_organization"])
        self.assertIsNone(parsed["account_id"])


class CloudFrontPrincipalTests(unittest.TestCase):
    def test_oai_is_trusted_aws_not_unknown(self):
        parsed = parse_principal_value("AWS", CLOUDFRONT_OAI_ARN)
        self.assertEqual(parsed["kind"], "cloudfront")
        self.assertIsNone(parsed["account_id"])
        self.assertEqual(parsed["label"], "CloudFront OAI EI92CX6OGEMUI")
        classification, vendor, trusted = classify_parsed_principal(
            parsed,
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(classification, "trusted")
        self.assertIsNone(vendor)
        self.assertEqual(trusted["source"], "aws_cloudfront")
        self.assertEqual(trusted["name"], "Amazon CloudFront")

    def test_oac_label(self):
        parsed = parse_principal_value("AWS", CLOUDFRONT_OAC_ARN)
        self.assertEqual(parsed["kind"], "cloudfront")
        self.assertEqual(parsed["label"], "CloudFront OAC E1ABCDEF")

    def test_s3_bucket_policy_oai_is_not_leftover(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": CLOUDFRONT_OAI_ARN},
                    "Action": "s3:GetObject",
                }
            },
            resource="arn:aws:s3:::asd.zoph.io",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["classification"], "trusted")
        self.assertEqual(grants[0]["principal_label"], "CloudFront OAI EI92CX6OGEMUI")
        self.assertEqual(totals_from_grants(grants)["unknown"], 0)
        self.assertEqual(totals_from_grants(grants)["trusted"], 1)


class ClassifyTests(unittest.TestCase):
    def test_vendor_match(self):
        parsed = parse_principal_value("AWS", "444455556666")
        classification, vendor, trusted = classify_parsed_principal(
            parsed,
            trusted_accounts={},
            account_to_vendor={"444455556666": {"name": "Datadog"}},
            current_account_id="111122223333",
        )
        self.assertEqual(classification, "vendor")
        self.assertEqual(vendor["name"], "Datadog")
        self.assertIsNone(trusted)

    def test_foreign_org_is_unknown_even_if_management_account_is_trusted(self):
        parsed = parse_principal_value(
            "AWS", FOREIGN_ORG_ARN, our_organization_id="o-ours"
        )
        classification, vendor, trusted = classify_parsed_principal(
            parsed,
            trusted_accounts={"999999999999": {"name": "Someone", "source": "yaml_file"}},
            account_to_vendor={"999999999999": {"name": "Vendor"}},
            current_account_id="111122223333",
        )
        self.assertEqual(classification, "unknown")
        self.assertIsNone(vendor)
        self.assertIsNone(trusted)

    def test_our_org_is_trusted(self):
        parsed = parse_principal_value(
            "AWS", OUR_ORG_ARN, our_organization_id="o-ours"
        )
        classification, _, trusted = classify_parsed_principal(
            parsed,
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(classification, "trusted")
        self.assertEqual(trusted["source"], "aws_org")


class TrustPolicyGrantTests(unittest.TestCase):
    TRUSTED = {"222222222222": {"name": "Prod", "source": "yaml_file"}}
    VENDORS = {"333333333333": {"name": "Datadog", "type": "third-party", "source": []}}

    def _grants(self, policy):
        return grants_from_policy_document(
            policy,
            resource="arn:aws:iam::111122223333:role/Example",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts=self.TRUSTED,
            account_to_vendor=self.VENDORS,
            current_account_id="111122223333",
        )

    def test_skips_same_account(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "sts:AssumeRole",
            },
        }
        self.assertEqual(self._grants(policy), [])

    def test_skips_service_principals(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        }
        self.assertEqual(self._grants(policy), [])

    def test_public_wildcard(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        }
        grants = self._grants(policy)
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["classification"], "public")
        self.assertTrue(grants[0]["is_public"])

    def test_github_oidc_is_federated_not_self(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Federated": GITHUB_OIDC_ARN},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                    },
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": "repo:acme/app:*"
                    },
                },
            }
        }
        grants = self._grants(policy)
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["classification"], "federated")
        self.assertIsNone(grants[0]["principal_account_id"])
        self.assertFalse(grants[0]["missing_oidc_subject"])
        self.assertEqual(grants[0]["principal_label"], "GitHub Actions OIDC")

    def test_github_oidc_missing_sub_and_aud(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Federated": GITHUB_OIDC_ARN},
                "Action": "sts:AssumeRole",
            }
        }
        grants = self._grants(policy)
        self.assertTrue(grants[0]["missing_oidc_subject"])
        self.assertEqual(len(grants[0]["oidc_gaps"]), 2)

    def test_gitlab_oidc_missing_sub(self):
        gaps = oidc_condition_gaps(GITLAB_OIDC_ARN, {})
        self.assertEqual(gaps, ["oidc:sub"])

    def test_vendor_missing_external_id_is_per_statement(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "333333333333"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "222222222222"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"sts:ExternalId": "abc"}
                    },
                },
            ]
        }
        grants = self._grants(policy)
        by_acct = {g["principal_account_id"]: g for g in grants}
        self.assertTrue(by_acct["333333333333"]["missing_external_id"])
        self.assertEqual(by_acct["333333333333"]["classification"], "vendor")
        self.assertFalse(by_acct["222222222222"]["missing_external_id"])
        self.assertEqual(by_acct["222222222222"]["classification"], "trusted")

    def test_trusted_without_external_id_is_not_confused_deputy_leftover(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "222222222222"},
                "Action": "sts:AssumeRole",
            }
        }
        grants = self._grants(policy)
        self.assertEqual(grants[0]["classification"], "trusted")
        self.assertFalse(grants[0]["missing_external_id"])

    def test_org_bootstrap_role_skips_external_id_even_if_unknown(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "567589703415"},
                    "Action": "sts:AssumeRole",
                }
            },
            resource="arn:aws:iam::111122223333:role/OrganizationAccountAccessRole",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(grants[0]["classification"], "unknown")
        self.assertFalse(grants[0]["missing_external_id"])

    def test_one_principal_per_grant(self):
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": ["333333333333", "444455556666"]},
                "Action": "sts:AssumeRole",
            }
        }
        grants = self._grants(policy)
        self.assertEqual(len(grants), 2)


class RamPermissionTests(unittest.TestCase):
    def test_statement_shape(self):
        doc = '{"Effect":"Allow","Action":["ec2:RunInstances","ec2:TerminateInstances"]}'
        self.assertEqual(
            actions_from_ram_permission(doc),
            ["ec2:RunInstances", "ec2:TerminateInstances"],
        )

    def test_policy_shape(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ram:AcceptResourceShareInvitation"}],
        }
        self.assertEqual(
            actions_from_ram_permission(doc),
            ["ram:AcceptResourceShareInvitation"],
        )


class BuiltinVendorTests(unittest.TestCase):
    def test_redshift_support_alias_is_merged(self):
        merged = merge_builtin_vendors({})
        self.assertEqual(merged["784127676232"]["name"], "Amazon Redshift Support")

    def test_community_list_wins(self):
        merged = merge_builtin_vendors(
            {"784127676232": {"name": "Community Name", "source": []}}
        )
        self.assertEqual(merged["784127676232"]["name"], "Community Name")


class TotalsTests(unittest.TestCase):
    def test_counts_classifications(self):
        grants = [
            {"classification": "public", "is_public": True},
            {"classification": "federated", "missing_oidc_subject": True, "oidc_gaps": ["x"]},
            {"classification": "unknown"},
            {
                "classification": "unknown",
                "never_expires": True,
                "credential_status": "Active",
            },
            {"classification": "vendor", "missing_external_id": True},
        ]
        totals = totals_from_grants(grants)
        self.assertEqual(totals["public"], 1)
        self.assertEqual(totals["federated"], 1)
        self.assertEqual(totals["unknown"], 2)
        self.assertEqual(totals["vendors"], 1)
        self.assertEqual(totals["missing_oidc_subject"], 1)
        self.assertEqual(totals["missing_external_id"], 1)
        self.assertEqual(totals["never_expires"], 1)
        self.assertEqual(totals["findings"], 5)


if __name__ == "__main__":
    unittest.main()
