# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the ADR 0002 enclave-monitoring layer in the Terraform engine.

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_monitoring_tf.py

Emits Terraform for the shipped profiles into a temp dir and asserts on the
generated HCL text. No AWS credentials or toolchains needed.
"""
import copy, os, re, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "emitters"))
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402
import terraform_emitter  # noqa: E402

ALL_PROFILES = sorted(f for f in os.listdir(PROFILES) if f.endswith(".json") and not f.startswith("_"))
COMMERCIAL = "fedramp-moderate-hipaa.commercial.json"
GOVCLOUD = [p for p in ALL_PROFILES if ".govcloud." in p]

EVENT_RULES = ["guardduty", "securityhub", "inspector", "config-compliance", "backup", "secret-rotation",
               "access-analyzer"]
CT_ALARMS = ["unauthorized-api", "console-no-mfa", "root-usage", "iam-policy-changes", "cloudtrail-changes",
             "console-auth-failures", "kms-key-disable-or-delete", "s3-bucket-policy-changes", "config-changes",
             "security-group-changes", "nacl-changes", "network-gateway-changes", "route-table-changes",
             "vpc-changes", "organizations-changes", "break-glass-assumed"]
HEALTH_ALARMS = ["bedrock-throttles", "bedrock-server-errors", "bedrock-invocation-log-delivery",
                 "guardrail-interventions", "gateway-system-errors", "gateway-throttles"]


def _emit(name, mutate=None):
    r, prof = sgea.resolve(os.path.join(PROFILES, name))
    if mutate:
        r = copy.deepcopy(r)
        mutate(r)
    d = tempfile.mkdtemp(prefix="sgea-mon-")
    terraform_emitter.emit(r, prof, d, ROOT)
    return r, d


def _read(d, *parts):
    return open(os.path.join(d, *parts)).read()


def _mon(d):
    return _read(d, "modules", "enclave-monitoring", "main.tf")


def _var_default(text, name):
    m = re.search(r'variable "%s" \{(.*?)\n\}' % re.escape(name), text, re.S)
    assert m, name
    d = re.search(r"default\s*=\s*(.+)", m.group(1))
    return d.group(1).strip()


def test_module_emitted_and_wired_with_toggle():
    _, d = _emit(COMMERCIAL)
    for f in ("versions.tf", "variables.tf", "main.tf", "outputs.tf", "README.md"):
        assert os.path.exists(os.path.join(d, "modules", "enclave-monitoring", f)), f
    main = _read(d, "main.tf")
    assert 'module "enclave_monitoring"' in main
    assert re.search(r'count\s+= var\.manage_monitoring \? 1 : 0', main)
    assert "module.enclave_logging.monitoring_topic_arn" in main
    assert "module.enclave_logging.cloudtrail_log_group" in main
    assert 'awscc = { source = "hashicorp/awscc"' in _read(d, "providers.tf")


def test_toggle_defaults_per_adr():
    _, d = _emit(COMMERCIAL)
    v = _read(d, "variables.tf")
    expected = {"manage_monitoring": "true", "create_access_analyzer": "true",
                "create_unused_access_analyzer": "false", "manage_transaction_search": "true",
                "monthly_budget_usd": "0", "create_cost_anomaly_monitor": "false",
                "create_break_glass_role": "false", "break_glass_principal_arns": "[]",
                "guardrail_intervention_threshold": "50"}
    for name, default in expected.items():
        assert _var_default(v, name) == default, (name, _var_default(v, name))


def test_all_rule_and_alarm_names_present():
    _, d = _emit(COMMERCIAL)
    m = _mon(d)
    assert 'name          = "sgea-${var.env}-evt-${each.key}"' in m
    for rule in EVENT_RULES:
        assert re.search(r"^\s+%s = \{" % re.escape(rule), m, re.M), rule
    assert "stack-drift" not in m and "aws.cloudformation" not in m   # CDK only
    assert 'alarm_name                = "sgea-${var.env}-ct-${each.key}"' in m
    for name in CT_ALARMS:
        assert re.search(r'^\s+"?%s"?\s+= "\{' % re.escape(name), m, re.M), name
    for name in HEALTH_ALARMS:
        assert 'alarm_name                = "sgea-${var.env}-%s"' % name in m, name
    assert 'namespace = "SGEA/${var.env}/CloudTrail"' in m


def test_patterns_and_thresholds_match_adr():
    _, d = _emit(COMMERCIAL)
    m = _mon(d)
    assert 'severity = [{ numeric = [">=", 7] }]' in m
    assert 'Workflow = { Status = ["NEW"] }' in m
    assert '\\"*UnauthorizedOperation\\"' in m and '\\"AccessDenied*\\"' in m
    assert '$.userIdentity.invokedBy NOT EXISTS' in m
    gr = m.split('resource "aws_cloudwatch_metric_alarm" "guardrail_interventions"')[1].split("\n}\n")[0]
    assert "GuardrailArn = var.guardrail_arn" in gr and "GuardrailVersion = var.guardrail_version" in gr
    assert re.search(r"threshold\s+= var\.guardrail_intervention_threshold", gr)
    gw = m.split('resource "aws_cloudwatch_metric_alarm" "gateway_system_errors"')[1].split("\n}\n")[0]
    assert 'Operation = "InvokeGateway"' in gw and 'Protocol = "MCP"' in gw and "Resource = var.gateway_arn" in gw
    log = m.split('resource "aws_cloudwatch_metric_alarm" "bedrock_invocation_log_delivery"')[1].split("\n}\n")[0]
    assert '"Minimum"' in log and re.search(r"period\s+= 900", log) and '"LessThanThreshold"' in log
    assert 'indexing_percentage = 1' in m and '"aws_cloudwatch_log_group" "spans"' not in m   # aws/spans is reserved
    assert 'type          = "ACCOUNT"' in m and 'type          = "ACCOUNT_UNUSED_ACCESS"' in m
    assert "unused_access_age = 90" in m


def test_gateway_alarms_absent_without_gateway():
    def drop(r):
        r["services"]["allow"] = [s for s in r["services"]["allow"] if s != "bedrock-agentcore"]
    _, d = _emit(COMMERCIAL, drop)
    m = _mon(d)
    assert "gateway-system-errors" not in m and "gateway-throttles" not in m
    assert 'variable "gateway_arn"' not in _read(d, "modules", "enclave-monitoring", "variables.tf")
    assert "gateway_arn" not in _read(d, "main.tf").split('module "enclave_monitoring"')[1].split("\n}\n")[0]


def test_invocation_log_alarm_only_with_invocation_logging():
    def off(r):
        r["logging"]["model_invocation_logging"] = False
    _, d = _emit(COMMERCIAL, off)
    assert "bedrock-invocation-log-delivery" not in _mon(d)


def test_budgets_and_anomaly_commercial_only():
    _, d = _emit(COMMERCIAL)
    m = _mon(d)
    assert 'resource "aws_budgets_budget" "monthly"' in m and '"sgea-${var.env}-monthly-cost"' in m
    assert 'resource "aws_ce_anomaly_monitor" "services"' in m and 'resource "aws_ce_anomaly_subscription" "anomalies"' in m
    assert '"ANOMALY_TOTAL_IMPACT_ABSOLUTE"' in m and 'values        = ["100"]' in m
    assert GOVCLOUD
    for name in GOVCLOUD:
        _, d = _emit(name)
        m = _mon(d)
        assert "aws_budgets_budget" not in m and "aws_ce_anomaly" not in m, name
        assert re.search(r"cost_publishers\s+= false", _read(d, "main.tf")), name


def test_break_glass_only_with_toggle():
    _, d = _emit(COMMERCIAL)
    main = _read(d, "main.tf")
    role = main.split('resource "aws_iam_role" "break_glass"')[1].split("\n}\n")[0]
    assert re.search(r"count\s+= var\.create_break_glass_role \? 1 : 0", role)
    assert '"sgea-${var.env}-break-glass"' in role
    assert '"aws:MultiFactorAuthPresent" = "true"' in role and '"aws:MultiFactorAuthAge" = "3600"' in role
    assert re.search(r"max_session_duration\s+= 3600", role) and '"sgea:role" = "break-glass"' in role
    att = main.split('resource "aws_iam_role_policy_attachment" "break_glass"')[1].split("\n}\n")[0]
    assert "count      = var.create_break_glass_role ? 1 : 0" in att and "policy/AdministratorAccess" in att
    assert re.search(r"break_glass\s+= var\.create_break_glass_role", main)
    assert 'output "break_glass_role_arn"' in _read(d, "outputs.tf")
    m = _mon(d)
    assert "var.break_glass ? {\n    break-glass-assumed" in m   # filter + alarm only with the role
    assert "aws_iam_role_policy\"" not in main                 # no inline role policy


def test_key_policy_and_topic_policy_statements():
    _, d = _emit(COMMERCIAL)
    kms = _read(d, "modules", "enclave-kms", "main.tf")
    stmt = re.split(r'sid\s+= "EventDeliveryToEncryptedSns"', kms)[1].split("},")[0]
    for svc in ("events.amazonaws.com", "budgets.amazonaws.com", "costalerts.amazonaws.com"):
        assert svc in stmt, svc
    assert 'local.arn == "aws-us-gov" ? ["events.amazonaws.com"]' in stmt   # cost publishers only outside GovCloud
    assert '"kms:GenerateDataKey*", "kms:Decrypt"' in stmt and '"aws:SourceAccount"' in stmt
    log = _read(d, "modules", "enclave-logging", "main.tf")
    tp = log.split('resource "aws_sns_topic_policy" "security_alarms"')[1].split("\n}\n")[0]
    assert "rule/sgea-${var.env}-evt-*" in tp
    cw = tp.split('Sid       = "CloudWatchAlarms"')[1].split("},\n      {")[0]   # keeps existing alarms publishing
    assert "cloudwatch.amazonaws.com" in cw and '"aws:SourceAccount" = local.account' in cw
    for svc in ("events.amazonaws.com", "budgets.amazonaws.com", "costalerts.amazonaws.com", "cloudwatch.amazonaws.com"):
        assert svc in tp, svc
    main = _read(d, "main.tf")
    assert re.search(r"event_publishers\s+= var\.manage_monitoring", main)
    assert re.search(r"cost_publishers\s+= var\.manage_monitoring && \(var\.monthly_budget_usd > 0 \|\| var\.create_cost_anomaly_monitor\)", main)


def test_spans_log_group_left_to_xray_with_post_deploy_controls():
    """aws/spans is reserved (X-Ray creates it): no resource; MANUAL-STEPS applies the CMK and the pack retention."""
    import manual_steps, derived
    r, d = _emit(COMMERCIAL)
    assert '"aws_cloudwatch_log_group" "spans"' not in _mon(d)
    md = manual_steps.render(r, ROOT, ["terraform"])
    days = derived.log_retention_days(r, ROOT)
    assert "associate-kms-key --log-group-name aws/spans" in md and "--retention-in-days %d" % days in md


def _run():
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(e))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(_run())
