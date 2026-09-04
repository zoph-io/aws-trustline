# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Victor Grenu / zoph.io
"""Unit tests for grant-row classification (no AWS calls)."""

from __future__ import annotations

import unittest

from grants import (
    actions_from_ram_permission,
    apply_live_trust_conditions,
    apply_s3_effective_public,
    choose_external_analyzer,
    classify_parsed_principal,
    extract_account_id_from_iam_value,
    flatten_condition_keys,
    grant_resource_label,
    grants_from_policy_document,
    index_known_accounts,
    merge_builtin_vendors,
    oidc_condition_gaps,
    parse_principal_value,
    parties_from_grants,
    report_scope_label,
    totals_from_grants,
    dedupe_access_analyzer_grants,
)


GITHUB_OIDC_ARN = (
    "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
)
GITLAB_OIDC_ARN = "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
FOREIGN_ORG_ARN = "arn:aws:organizations::999999999999:organization/o-foreign"
OUR_ORG_ARN = "arn:aws:organizations::111122223333:organization/o-ours"
OUR_OU_ARN = "arn:aws:organizations::111122223333:ou/o-ours/ou-abcd1234"
CLOUDFRONT_OAI_ARN = (
    "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity EEXAMPLEOAIID"
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
        self.assertEqual(parsed["label"], "CloudFront OAI EEXAMPLEOAIID")
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
            resource="arn:aws:s3:::example-bucket",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["classification"], "trusted")
        self.assertEqual(grants[0]["principal_label"], "CloudFront OAI EEXAMPLEOAIID")
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
                    "Principal": {"AWS": "555555555555"},
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


class NameLookupTests(unittest.TestCase):
    def test_unknown_account_is_labeled_not_in_dataset(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "555555555555"},
                    "Action": "sts:AssumeRole",
                }
            },
            resource="arn:aws:iam::111122223333:role/Example",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(grants[0]["classification"], "unknown")
        self.assertEqual(grants[0]["name_source"], "not_in_dataset")
        self.assertEqual(
            grants[0]["principal_label"],
            "555555555555 (not in known_aws_accounts)",
        )

    def test_vendor_name_source_is_fwdcloudsec(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "333333333333"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
                }
            },
            resource="arn:aws:iam::111122223333:role/Example",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={"333333333333": {"name": "Datadog", "type": "third-party"}},
            current_account_id="111122223333",
        )
        self.assertEqual(grants[0]["name_source"], "fwd:cloudsec")
        self.assertIn("Datadog", grants[0]["principal_label"])

    def test_yaml_trusted_source(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "222222222222"},
                    "Action": "sts:AssumeRole",
                }
            },
            resource="arn:aws:iam::111122223333:role/Example",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={"222222222222": {"name": "Prod", "source": "yaml_file"}},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertEqual(grants[0]["name_source"], "yaml_file")

    def test_parties_group_two_grants_for_one_account(self):
        role = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "333333333333"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
                }
            },
            resource="arn:aws:iam::111122223333:role/One",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={"333333333333": {"name": "Datadog"}},
            current_account_id="111122223333",
        )
        bucket = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "333333333333"},
                    "Action": "s3:GetObject",
                }
            },
            resource="example-bucket",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={"333333333333": {"name": "Datadog"}},
            current_account_id="111122223333",
        )
        parties = parties_from_grants(role + bucket)
        self.assertEqual(len(parties), 1)
        self.assertEqual(parties[0]["grant_count"], 2)
        self.assertEqual(parties[0]["account_id"], "333333333333")
        self.assertEqual(parties[0]["classification"], "vendor")

    def test_unresolved_sorts_before_vendor(self):
        unknown = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "555555555555"},
                    "Action": "sts:AssumeRole",
                }
            },
            resource="arn:aws:iam::111122223333:role/A",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        vendor = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "333333333333"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
                }
            },
            resource="arn:aws:iam::111122223333:role/B",
            resource_type="AWS::IAM::Role",
            mechanism="trust_policy",
            trusted_accounts={},
            account_to_vendor={"333333333333": {"name": "Datadog"}},
            current_account_id="111122223333",
        )
        parties = parties_from_grants(vendor + unknown)
        self.assertEqual(parties[0]["classification"], "unknown")
        self.assertEqual(parties[1]["classification"], "vendor")

    def test_bpa_drops_public_from_inventory(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                }
            },
            resource="example-bucket",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        apply_s3_effective_public(grants[0], False)
        self.assertTrue(grants[0]["blocked_by_bpa"])
        self.assertFalse(grants[0]["is_public"])
        self.assertEqual(grants[0]["classification"], "blocked_public")
        self.assertEqual(parties_from_grants(grants), [])
        totals = totals_from_grants(grants)
        self.assertEqual(totals["public"], 0)
        self.assertEqual(totals["blocked_public"], 1)

    def test_bpa_unknown_keeps_public(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                }
            },
            resource="example-bucket",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        apply_s3_effective_public(grants[0], None)
        self.assertTrue(grants[0]["is_public"])
        self.assertEqual(grants[0]["classification"], "public")

    def test_index_known_accounts_skips_bad_ids(self):
        indexed = index_known_accounts(
            [
                {"name": "Datadog", "accounts": ["333333333333", "nope", 444455556666]},
            ]
        )
        self.assertEqual(indexed["333333333333"]["name"], "Datadog")
        self.assertEqual(indexed["444455556666"]["name"], "Datadog")
        self.assertNotIn("nope", indexed)

    def test_two_cloudfront_oais_are_one_party(self):
        first = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": CLOUDFRONT_OAI_ARN},
                    "Action": "s3:GetObject",
                }
            },
            resource="arn:aws:s3:::example-a",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        second = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": CLOUDFRONT_OAC_ARN},
                    "Action": "s3:GetObject",
                }
            },
            resource="arn:aws:s3:::example-b",
            resource_type="AWS::S3::Bucket",
            mechanism="s3_bucket_policy",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        parties = parties_from_grants(first + second)
        self.assertEqual(len(parties), 1)
        self.assertEqual(parties[0]["name"], "Amazon CloudFront")
        self.assertEqual(parties[0]["grant_count"], 2)
        self.assertEqual(parties[0]["classification"], "trusted")


class AnalyzerChoiceTests(unittest.TestCase):
    def test_auto_prefers_account_over_organization(self):
        chosen = choose_external_analyzer(
            [
                {"type": "ORGANIZATION", "arn": "arn:org"},
                {"type": "ACCOUNT", "arn": "arn:acct"},
            ],
            "auto",
        )
        self.assertEqual(chosen["type"], "ACCOUNT")

    def test_auto_falls_back_to_organization(self):
        chosen = choose_external_analyzer(
            [{"type": "ORGANIZATION", "arn": "arn:org"}],
            "auto",
        )
        self.assertEqual(chosen["type"], "ORGANIZATION")

    def test_report_scope_auto_is_account(self):
        self.assertEqual(report_scope_label("auto"), "account")
        self.assertEqual(report_scope_label("organization"), "organization")


class ResourceLabelTests(unittest.TestCase):
    def test_sns_digit_name_includes_type(self):
        label = grant_resource_label(
            {
                "resource": "arn:aws:sns:eu-west-1:111122223333:1",
                "resource_type": "AWS::SNS::Topic",
            }
        )
        self.assertEqual(label, "1 (SNS Topic)")

    def test_kms_uuid_includes_type(self):
        label = grant_resource_label(
            {
                "resource": (
                    "arn:aws:kms:eu-west-1:111122223333:key/"
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                ),
                "resource_type": "AWS::KMS::Key",
            }
        )
        self.assertIn("KMS Key", label)
        self.assertIn("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", label)

    def test_iam_role_name_is_enough(self):
        label = grant_resource_label(
            {
                "resource": "arn:aws:iam::111122223333:role/GhA-Example",
                "resource_type": "AWS::IAM::Role",
            }
        )
        self.assertEqual(label, "GhA-Example")


class OidcConditionShapeTests(unittest.TestCase):
    def test_aa_flat_condition_keys_count_as_present(self):
        gaps = oidc_condition_gaps(
            GITHUB_OIDC_ARN,
            {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": "repo:acme/app:*",
            },
        )
        self.assertEqual(gaps, [])
        keys = flatten_condition_keys(
            {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": "repo:acme/app:*",
            }
        )
        self.assertIn("token.actions.githubusercontent.com:sub", keys)

    def test_empty_aa_condition_is_not_kept_when_live_policy_has_sub_aud(self):
        grants = grants_from_policy_document(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"Federated": GITHUB_OIDC_ARN},
                    "Action": "sts:AssumeRole",
                }
            },
            resource="arn:aws:iam::111122223333:role/GhA-Example",
            resource_type="AWS::IAM::Role",
            mechanism="access_analyzer",
            trusted_accounts={},
            account_to_vendor={},
            current_account_id="111122223333",
        )
        self.assertTrue(grants[0]["missing_oidc_subject"])
        live = {
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
        self.assertTrue(apply_live_trust_conditions(grants[0], live))
        self.assertFalse(grants[0]["missing_oidc_subject"])
        self.assertEqual(grants[0]["oidc_gaps"], [])
        self.assertEqual(grants[0]["condition_source"], "iam_get_role")


class DedupeAccessAnalyzerTests(unittest.TestCase):
    def test_prefers_account_analyzer_and_drops_duplicate_iam_role(self):
        base = {
            "resource": "arn:aws:iam::111122223333:role/GhA-Example",
            "principal_kind": "federated",
            "principal_account_id": None,
            "principal_label": "GitHub Actions OIDC",
            "is_public": False,
            "mechanism": "access_analyzer",
        }
        org_row = {**base, "analyzer_type": "ORGANIZATION", "id": "org"}
        acct_row = {**base, "analyzer_type": "ACCOUNT", "id": "acct"}
        kept, dropped = dedupe_access_analyzer_grants([org_row, acct_row])
        self.assertEqual(dropped, 1)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["analyzer_type"], "ACCOUNT")


if __name__ == "__main__":
    unittest.main()
