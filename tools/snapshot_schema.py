#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Snapshot the provider-schema slice the inferred service controls and config-rule plan checks reference.

tools/build_catalog.py validates every resource/attribute named in
sources/inferred/service-controls.yaml against this snapshot, so an inferred
setting can never point at a field the provider does not have.

Usage (from an initialized Terraform dir, e.g. an exported build):
    terraform -chdir=build/<profile>/terraform providers schema -json > /tmp/schema.json
    python -I tools/snapshot_schema.py /tmp/schema.json build/<profile>/terraform/.terraform.lock.hcl
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "sources", "provider-schema", "bedrock-agentcore-slice.json")
KEEP = re.compile(r"^(awscc_bedrock|aws_bedrock)")
EXTRA = {"aws_ecr_repository", "aws_cloudwatch_log_group", "aws_vpc_endpoint", "aws_cloudtrail",
         "aws_kms_key", "aws_s3_bucket", "aws_s3_bucket_versioning", "aws_s3_bucket_public_access_block",
         "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_ownership_controls",
         "aws_s3_bucket_policy", "aws_s3_bucket_object_lock_configuration", "aws_dynamodb_table",
         "aws_rds_cluster", "aws_rds_cluster_instance", "aws_backup_vault", "aws_backup_plan",
         "aws_backup_vault_lock_configuration", "aws_config_conformance_pack", "aws_s3_bucket_logging",
         "aws_s3_bucket_replication_configuration", "aws_s3_bucket_notification",
         "aws_s3_bucket_lifecycle_configuration", "aws_ecr_lifecycle_policy", "aws_lambda_function",
         "aws_networkfirewall_firewall", "aws_networkfirewall_firewall_policy", "aws_networkfirewall_rule_group",
         "aws_networkfirewall_logging_configuration", "aws_guardduty_detector", "aws_securityhub_account",
         "aws_securityhub_standards_subscription", "aws_flow_log", "aws_cloudwatch_log_subscription_filter",
         "aws_ebs_encryption_by_default", "aws_ebs_default_kms_key", "aws_ebs_snapshot_block_public_access",
         "aws_s3_account_public_access_block", "aws_default_security_group", "aws_iam_account_password_policy",
         "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy", "aws_backup_selection",
         "aws_lambda_permission", "aws_cloudwatch_metric_alarm", "aws_sns_topic", "aws_inspector2_enabler", "aws_backup_vault_policy"}


def main(schema_path, lock_path):
    schema = json.load(open(schema_path))["provider_schemas"]
    lock = open(lock_path).read()
    out = {"providers": {}, "resource_schemas": {}}
    for addr, prov in schema.items():
        m = re.search(r'provider "' + re.escape(addr) + r'" \{\s*version\s*=\s*"([^"]+)"', lock)
        out["providers"][addr] = m.group(1) if m else None
        for name, res in prov.get("resource_schemas", {}).items():
            if KEEP.match(name) or name in EXTRA:
                out["resource_schemas"][name] = res["block"]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("wrote %s (%d resources; providers %s)" % (OUT, len(out["resource_schemas"]), out["providers"]))


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
