# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Derived control values shared by both emitters.

The resolved config holds the control decisions; a few need deterministic
derivation before IaC can use them (CloudWatch's accepted retention values,
CloudTrail data-event type names, VPC endpoint names, conformance-pack backup
parameters, replica region). They are computed ONCE here: the Terraform emitter
bakes them into HCL, the CDK emitter writes them to config.json `_derived`, so
the two outputs cannot disagree.
"""
import json, os

try:
    from . import policy_library
    from .guardrail_map import PII_ENTITIES, PHI_ENTITIES, CONTEXTUAL_ENTITIES, INPUT_ONLY_FILTERS, FILTER_ORDER
except ImportError:  # in-repo fallback import (sgea._load_emitters)
    import policy_library
    from guardrail_map import PII_ENTITIES, PHI_ENTITIES, CONTEXTUAL_ENTITIES, INPUT_ONLY_FILTERS, FILTER_ORDER


# CloudWatch Logs accepts only these retention values; round the resolved
# logging.retention_days UP so retention is never shorter than the baseline.
CW_RETENTION_DAYS = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096,
                     1827, 2192, 2557, 2922, 3288, 3653]

# logging.cloudtrail_data_events vocabulary -> CloudTrail advanced-selector resources.type.
# Confirm on first sandbox apply: CloudTrail validates these at the API, not terraform validate.
DATA_EVENT_TYPES = {
    "bedrock": ["AWS::Bedrock::AgentAlias", "AWS::Bedrock::FlowAlias", "AWS::Bedrock::Guardrail",
                "AWS::Bedrock::InlineAgent", "AWS::Bedrock::KnowledgeBase", "AWS::Bedrock::Model"],
    "bedrock-agentcore": ["AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::Gateway",
                          "AWS::BedrockAgentCore::Memory"],
    "s3-enclave-buckets": ["AWS::S3::Object"],
}


def cw_retention(days):
    return next((d for d in CW_RETENTION_DAYS if d >= days), CW_RETENTION_DAYS[-1])


CW_RULE_DEFAULT_MIN_RETENTION = 365  # cw-loggroup-retention-period-check default when the pack sets no MinRetentionTime


def log_retention_days(resolved, root):
    """CloudWatch retention: the baseline's logging.retention_days, raised to the pack rule's minimum
    (cw-loggroup-retention-period-check MinRetentionTime, AWS default 365 when the pack leaves it blank)."""
    days = resolved["logging"]["retention_days"]
    p = catalog_rules(resolved, root).get("cw-loggroup-retention-period-check")
    if p is not None:
        days = max(days, int(p.get("MinRetentionTime") or CW_RULE_DEFAULT_MIN_RETENTION))
    return cw_retention(days)


def data_event_types(resolved):
    events = list(resolved.get("logging", {}).get("cloudtrail_data_events", []))
    if "bedrock-agentcore" in resolved.get("services", {}).get("allow", []) and "bedrock-agentcore" not in events:
        events.append("bedrock-agentcore")  # SGEA-AC-LOG-03
    out = []
    for e in events:
        out += [t for t in DATA_EVENT_TYPES.get(e, []) if t not in out]
    return out


# services.allow ids -> interface endpoint suffixes; foundation endpoints always added.
ENDPOINT_SERVICES = {
    "bedrock": ["bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime"],
    "bedrock-agentcore": ["bedrock-agentcore", "bedrock-agentcore.gateway"],
    "kms": ["kms"], "cloudwatch": ["logs", "monitoring"], "lambda": ["lambda"],
    "dynamodb": [], "s3": [], "sns": ["sns"], "eventbridge": ["events"], "firehose": ["kinesis-firehose"],
    "aurora-postgresql": ["rds", "rds-data"], "elasticache": ["elasticache"], "cognito": ["cognito-idp"],
    "cloudtrail": [],
}
FOUNDATION_ENDPOINTS = ["sts", "secretsmanager", "ecr.api", "ecr.dkr", "ssm",
                        "xray"]   # OpenTelemetry (ADOT) spans from the VPC-only runtime and Lambdas to X-Ray / Transaction Search


def endpoint_services(resolved):
    out = []
    for svc in resolved.get("services", {}).get("allow", []):
        out += [e for e in ENDPOINT_SERVICES.get(svc, []) if e not in out]
    return out + [e for e in FOUNDATION_ENDPOINTS if e not in out]


def catalog_rules(resolved, root):
    """config_rule -> merged parameters across the profile's baseline catalogs."""
    rules = {}
    for b in resolved["baselines"]:
        path = os.path.join(root or ".", "catalog", b + ".json")
        if not os.path.exists(path):
            raise SystemExit("catalog missing: %s (run: python -I tools/build_catalog.py)" % path)
        for svc in json.load(open(path))["services"].values():
            for r in svc:
                rules.setdefault(r["config_rule"], {}).update(r["parameters"])
    return rules


def backup_policy(resolved, root):
    """Backup retention / frequency / vault lock from the composed conformance packs."""
    rules = catalog_rules(resolved, root)
    days = [int(p["requiredRetentionDays"]) for r, p in rules.items() if "requiredRetentionDays" in p]
    return {
        "retention_days": max(days) if days else 35,
        "vault_lock": "backup-recovery-point-manual-deletion-disabled" in rules,
        "rules": sorted(r for r in rules if r.startswith(("rds-", "aurora-", "backup-", "db-instance-"))),
    }


def _truthy(v):
    return str(v).strip().lower() == "true"


def account_baseline(resolved, root):
    """Account-level settings the composed packs require, strictest parameter wins."""
    rules = catalog_rules(resolved, root)
    pw = {}
    for name in ("iam-password-policy", "iam-password-policy-2"):
        for k, v in (rules.get(name) or {}).items():
            if k in ("MinimumPasswordLength", "PasswordReusePrevention"):
                pw[k] = max(int(v), pw.get(k, 0))
            elif k == "MaxPasswordAge":
                pw[k] = min(int(v), pw.get(k, 10 ** 6))
            else:
                pw[k] = pw.get(k, False) or _truthy(v)
    password = None
    if "iam-password-policy" in rules or "iam-password-policy-2" in rules:
        password = {"minimum_password_length": pw.get("MinimumPasswordLength", 14),
                    "password_reuse_prevention": pw.get("PasswordReusePrevention", 24),
                    "max_password_age": pw.get("MaxPasswordAge", 90),
                    "require_lowercase_characters": pw.get("RequireLowercaseCharacters", True),
                    "require_uppercase_characters": pw.get("RequireUppercaseCharacters", True),
                    "require_numbers": pw.get("RequireNumbers", True),
                    "require_symbols": pw.get("RequireSymbols", True)}
    lam = rules.get("lambda-concurrency-check")
    alarm = rules.get("cloudwatch-alarm-action-check") or {}
    return {
        "password_policy": password,
        "ebs_encryption_by_default": "ec2-ebs-encryption-by-default" in rules,
        "snapshot_block_public_access": "ebs-snapshot-public-restorable-check" in rules,
        "s3_account_public_access_block": "s3-account-level-public-access-blocks-periodic" in rules,
        "default_security_group_closed": "vpc-default-security-group-closed" in rules,
        "inspector_resource_types": sorted(t for r, t in (("inspector-ecr-scan-enabled", "ECR"),
                                                         ("inspector-lambda-standard-scan-enabled", "LAMBDA"),
                                                         ("inspector-ec2-scan-enabled", "EC2")) if r in rules),
        # lambda-concurrency-check: reserved concurrency inside [ConcurrencyLimitLow, ConcurrencyLimitHigh].
        "lambda_reserved_concurrency": int(lam["ConcurrencyLimitLow"]) if lam and lam.get("ConcurrencyLimitLow") else None,
        "alarm_insufficient_data_action": _truthy(alarm.get("insufficientDataActionRequired", "false")),
        "alarm_ok_action": _truthy(alarm.get("okActionRequired", "false")),
    }


def pack_template(root, fname):
    """Pinned AWS conformance-pack template + SGEA InputParameters overlays (sources/inferred/pack-parameter-overlays.json)."""
    text = open(os.path.join(root or ".", "sources", "conformance-packs", fname)).read()
    ov = json.load(open(os.path.join(root or ".", "sources", "inferred", "pack-parameter-overlays.json")))
    for rule, params in ov.items():
        if rule.startswith("_"):
            continue
        anchor = "      ConfigRuleName: %s\n" % rule
        if anchor not in text or "InputParameters" in text.split(anchor, 1)[1].split("Type: AWS::Config::ConfigRule", 1)[0]:
            continue  # rule absent, or the pack already parameterizes it
        block = "      InputParameters:\n" + "".join("        %s: '%s'\n" % (k, v) for k, v in params.items() if not k.startswith("_"))
        text = text.replace(anchor, anchor + block, 1)
    return text


def pack_resource_name(pack):
    return "sgea-" + "".join(c if c.isalnum() else "-" for c in pack.lower()).replace("--", "-")


def replica_region(resolved):
    """Log-store replica region: the first allowed region that is not the primary."""
    primary = resolved["regions"]["primary"]
    others = [r for r in resolved["regions"]["allowed"] if r != primary]
    if not others:
        raise SystemExit("regions.allowed needs a second region for the log-store replica")
    return others[0]


def conformance_pack_files(resolved):
    """CloudFormation-safe pack name -> template file name."""
    return {pack_resource_name(p): "Operational-Best-Practices-for-" + p + ".yaml"
            for p in resolved.get("evidence", {}).get("conformance_packs", [])}


def _regions_catalog(root):
    path = os.path.join(root or ".", "catalog", "_regions.json")
    return json.load(open(path)) if os.path.exists(path) else None


def policy_engine_available(resolved, root):
    """AWS::BedrockAgentCore::PolicyEngine is not offered in GovCloud (GovCloud User Guide)."""
    cat = _regions_catalog(root)
    if resolved.get("partition") != "aws-us-gov" or not cat:
        return True
    gov = cat["govcloud_differences"].get("bedrock-agentcore", {})
    return "AWS::BedrockAgentCore::PolicyEngine" not in gov.get("unavailable_cfn_types", [])


# Strictest model-authorization column needed by each baseline.
MODEL_COLUMN = {"fedramp-low": "fedramp_class_c", "fedramp-moderate": "fedramp_class_c",
                "fedramp-high": "fedramp_class_d_govcloud", "dod-il2": "fedramp_class_c",
                "dod-il4": "dod_il4_il5", "dod-il5": "dod_il4_il5"}


def authorized_models(resolved, root):
    """Bedrock models authorized for every composed baseline (AWS FedRAMP/DoD model table)."""
    cat = _regions_catalog(root)
    cols = [MODEL_COLUMN[b] for b in resolved["baselines"] if b in MODEL_COLUMN]
    if not cat or not cols:
        return None
    return sorted("%s %s" % (m["family"], m["model"]) for m in cat["bedrock_models"] if all(m[c] for c in cols))


def authorized_model_ids(resolved, root):
    """Model IDs (catalog/_regions.json bedrock_models.model_ids) authorized for every baseline."""
    cat = _regions_catalog(root)
    cols = [MODEL_COLUMN[b] for b in resolved["baselines"] if b in MODEL_COLUMN]
    if not cat or not cols:
        return None
    return sorted({i for m in cat["bedrock_models"] if all(m[c] for c in cols) for i in m["model_ids"]})


# DoD SRG levels that require a Secure Cloud Computing Architecture boundary.
SCCA_BASELINES = {"dod-il4", "dod-il5"}


def scca_required(resolved):
    return bool(SCCA_BASELINES & set(resolved["baselines"]))


def derive(resolved, root):
    """Everything an emitter needs beyond the resolved config, in one document."""
    g = resolved["guardrails"]
    return {
        "cloudwatch_retention_days": log_retention_days(resolved, root),
        "data_event_resource_types": data_event_types(resolved),
        "endpoint_services": endpoint_services(resolved),
        "backup": backup_policy(resolved, root),
        "replica_region": replica_region(resolved),
        "conformance_packs": conformance_pack_files(resolved),
        "policy_bundles": policy_library.bundles(resolved, authorized_model_ids(resolved, root)),
        "guardrail": {
            "pii_entities": PII_ENTITIES, "phi_entities": PHI_ENTITIES, "contextual_entities": CONTEXTUAL_ENTITIES,
            "input_only_filters": INPUT_ONLY_FILTERS, "filter_order": FILTER_ORDER,
            "tier": "STANDARD" if g.get("tier") == "standard-plus" else "CLASSIC",
            "enforce_account_wide": "L2_account_baseline" in g.get("levels", []),
            "gateway_tool_path": "gateway_tool_path" in g.get("levels", []),
        },
        "agentcore": "bedrock-agentcore" in resolved["services"]["allow"],
        "policy_engine_available": policy_engine_available(resolved, root),
        "account_baseline": account_baseline(resolved, root),
        "authorized_models": authorized_models(resolved, root),
        "authorized_model_ids": authorized_model_ids(resolved, root),
        "scca_required": scca_required(resolved),
        "aurora": resolved.get("vector_store") == "aurora-postgresql",
    }
