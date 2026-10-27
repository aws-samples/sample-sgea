# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the CDK enclave-monitoring layer (ADR 0002): synthesizes a commercial and a GovCloud
profile and inspects cdk.out/SgeaEnclave.template.json.

Runs two ways:
  - pytest:            pytest -q tests/test_monitoring_cdk.py
  - no dependencies:   python tests/test_monitoring_cdk.py

Needs node / npx and the npm registry (npm install of the pinned CDK toolchain); skipped otherwise.
No AWS credentials: `cdk synth` only, with the placeholder inputs `sgea verify` uses.
"""
import atexit, json, os, shutil, subprocess, sys, tempfile  # nosec B404

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, ROOT)
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402

COMMERCIAL = "fedramp-moderate-hipaa.commercial.json"
GOVCLOUD = "fedramp-high.govcloud.json"
ENV = sgea.VERIFY_CONTEXT["env"]
_STATE = {}


class _Skip(Exception):
    pass


def _skip(msg):
    try:
        import pytest
    except ImportError:
        raise _Skip(msg)
    pytest.skip(msg)


def _synth(profile, extra):
    """Export `profile` (CDK only), synthesize it with VERIFY_CONTEXT + `extra`, return the enclave template."""
    key = (profile, tuple(sorted(extra.items())))
    if key in _STATE:
        return _STATE[key]
    if not (shutil.which("node") and shutil.which("npx") and shutil.which("npm")):
        _skip("needs node / npx / npm (CDK toolchain)")
    if "work" not in _STATE:   # exports + node_modules are large: removed at interpreter exit
        _STATE["work"] = tempfile.mkdtemp(prefix="sgea-mon-")
        atexit.register(shutil.rmtree, _STATE["work"], True)
    work = _STATE["work"]
    out = os.path.join(work, str(len(_STATE)))
    sgea.main(["export", "--profile", os.path.join(PROFILES, profile), "--out", out, "--emit", "cdk", "--allow-unverified"])
    cdk = os.path.join(out, [d for d in os.listdir(out) if os.path.isdir(os.path.join(out, d, "cdk"))][0], "cdk")
    nm = _STATE.get("node_modules")
    if nm:   # same pinned package.json / lock for every profile: share one install
        os.symlink(nm, os.path.join(cdk, "node_modules"))
    else:
        r = subprocess.run(["npm", "install", "--silent"], cwd=cdk, check=False, capture_output=True)  # nosec B603 B607
        if r.returncode:
            _skip("npm install failed (offline?): " + r.stderr.decode()[-300:])
        _STATE["node_modules"] = os.path.join(cdk, "node_modules")
    ctx = dict(sgea.VERIFY_CONTEXT, **extra)
    args = [a for k, v in ctx.items() for a in ("-c", "sgea:%s=%s" % (k, v))]
    r = subprocess.run(["npx", "cdk", "synth", "--quiet", *args], cwd=cdk, check=False, capture_output=True)  # nosec B603 B607
    assert r.returncode == 0, r.stderr.decode()[-3000:]
    with open(os.path.join(cdk, "cdk.out", "SgeaEnclave.template.json")) as f:
        tpl = json.load(f)["Resources"]
    _STATE[key] = tpl
    return tpl


def _of(tpl, rtype):
    return [r.get("Properties", {}) for r in tpl.values() if r["Type"] == rtype]


def _names(tpl, rtype, prop):
    return {p[prop] for p in _of(tpl, rtype)}


def _commercial():
    return _synth(COMMERCIAL, {"monthlyBudgetUsd": "500"})


def _govcloud():
    return _synth(GOVCLOUD, {"monthlyBudgetUsd": "500"})


CT = ["unauthorized-api", "console-no-mfa", "root-usage", "iam-policy-changes", "cloudtrail-changes",
      "console-auth-failures", "kms-key-disable-or-delete", "s3-bucket-policy-changes", "config-changes",
      "security-group-changes", "nacl-changes", "network-gateway-changes", "route-table-changes", "vpc-changes",
      "organizations-changes"]
RULES = ["guardduty", "securityhub", "inspector", "config-compliance", "backup", "secret-rotation",
         "access-analyzer", "stack-drift"]


# ---- M1 event routing + drift detection ------------------------------------
def test_event_rules_target_the_alarm_topic():
    t = _commercial()
    rules = {p["Name"]: p for p in _of(t, "AWS::Events::Rule") if p.get("Name", "").startswith("sgea-%s-evt-" % ENV)}
    assert set(rules) == {"sgea-%s-evt-%s" % (ENV, n) for n in RULES}, sorted(rules)
    topic = [k for k, r in t.items() if r["Type"] == "AWS::SNS::Topic"
             and r["Properties"]["TopicName"] == "sgea-%s-security-alarms" % ENV][0]
    for p in rules.values():
        assert p["Targets"][0]["Arn"] == {"Ref": topic}
    gd = rules["sgea-%s-evt-guardduty" % ENV]["EventPattern"]
    assert gd["detail"]["severity"] == [{"numeric": [">=", 7]}]


def test_daily_drift_schedule_uses_partition_correct_universal_target():
    t = _commercial()
    (s,) = [p for p in _of(t, "AWS::Scheduler::Schedule") if p["Name"] == "sgea-%s-drift-detect" % ENV]
    assert s["ScheduleExpression"] == "rate(1 day)"
    arn = json.dumps(s["Target"]["Arn"])
    assert "AWS::Partition" in arn and ":scheduler:::aws-sdk:cloudformation:detectStackDrift" in arn
    assert json.loads(s["Target"]["Input"]) == {"StackName": "SgeaEnclave"}
    (role,) = [p for p in _of(t, "AWS::IAM::Role") if p.get("RoleName") == "sgea-%s-drift-scheduler" % ENV]
    assert not role.get("Policies")
    (trust,) = role["AssumeRolePolicyDocument"]["Statement"]   # Scheduler's aws:SourceArn is the schedule-group ARN
    assert ":schedule-group/default" in json.dumps(trust["Condition"]["ArnEquals"]["aws:SourceArn"])
    pols = [p for p in _of(t, "AWS::IAM::ManagedPolicy") if p.get("ManagedPolicyName") == "sgea-%s-drift-scheduler" % ENV]
    actions = sorted(a for st in pols[0]["PolicyDocument"]["Statement"] for a in st["Action"])
    assert actions == ["cloudformation:DetectStackDrift", "cloudformation:DetectStackResourceDrift"]


def test_no_inline_policies():
    for t in (_commercial(), _govcloud()):
        assert not _of(t, "AWS::IAM::Policy")
        assert not [p for p in _of(t, "AWS::IAM::Role") if p.get("Policies")]


# ---- M2 / M3 alarms ----------------------------------------------------------
def test_cloudtrail_filters_and_alarms():
    t = _commercial()
    alarms = _names(t, "AWS::CloudWatch::Alarm", "AlarmName")
    filters = _names(t, "AWS::Logs::MetricFilter", "FilterName")
    for n in CT:
        assert "sgea-%s-ct-%s" % (ENV, n) in alarms and "sgea-%s-ct-%s" % (ENV, n) in filters, n
    a = [p for p in _of(t, "AWS::CloudWatch::Alarm") if p["AlarmName"] == "sgea-%s-ct-root-usage" % ENV][0]
    assert (a["Statistic"], a["Period"], a["EvaluationPeriods"], a["Threshold"], a["TreatMissingData"]) == \
        ("Sum", 300, 1, 1, "notBreaching") and a["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
    assert a["Namespace"] == "SGEA/%s/CloudTrail" % ENV


def test_health_alarms():
    t = _commercial()
    alarms = _names(t, "AWS::CloudWatch::Alarm", "AlarmName")
    for n in ["bedrock-throttles", "bedrock-server-errors", "bedrock-invocation-log-delivery", "guardrail-interventions",
              "gateway-system-errors", "gateway-throttles"]:
        assert "sgea-%s-%s" % (ENV, n) in alarms, n


# ---- M4 cost / M5 analyzer / M6 transaction search ---------------------------
def test_budgets_and_anomaly_detection_commercial_only():
    c, g = _commercial(), _govcloud()
    assert [p["Budget"]["BudgetName"] for p in _of(c, "AWS::Budgets::Budget")] == ["sgea-%s-monthly-cost" % ENV]
    assert not _of(c, "AWS::CE::AnomalyMonitor")      # opt-in (sgea:createCostAnomalyMonitor): one SERVICE monitor per account
    for rtype in ("AWS::Budgets::Budget", "AWS::CE::AnomalyMonitor", "AWS::CE::AnomalySubscription"):
        assert not _of(g, rtype), rtype
    assert "sgea-%s-evt-guardduty" % ENV in _names(g, "AWS::Events::Rule", "Name")


def test_access_analyzer_and_transaction_search():
    t = _commercial()
    assert _names(t, "AWS::AccessAnalyzer::Analyzer", "AnalyzerName") == {"sgea-%s-external-access" % ENV}
    assert len(_of(t, "AWS::XRay::TransactionSearchConfig")) == 1
    # aws/spans is reserved (X-Ray creates it): the enclave must not try to create it.
    assert not [r for r in t.values() if r["Type"] == "AWS::Logs::LogGroup" and r["Properties"].get("LogGroupName") == "aws/spans"]


# ---- break-glass, key policy, topic policy, token vault ----------------------
def test_break_glass_absent_by_default():
    for t in (_commercial(), _govcloud()):
        assert not [p for p in _of(t, "AWS::IAM::Role") if p.get("RoleName", "").endswith("-break-glass")]
        assert "sgea-%s-ct-break-glass-assumed" % ENV not in _names(t, "AWS::CloudWatch::Alarm", "AlarmName")


def test_key_policy_admits_event_delivery():
    t = _commercial()
    stmts = [s for p in _of(t, "AWS::KMS::Key") for s in p["KeyPolicy"]["Statement"] if s.get("Sid") == "EventDeliveryToEncryptedSns"]
    assert len(stmts) == 1
    s = stmts[0]
    assert sorted(s["Principal"]["Service"]) == ["budgets.amazonaws.com", "costalerts.amazonaws.com", "events.amazonaws.com"]
    assert sorted(s["Action"]) == ["kms:Decrypt", "kms:GenerateDataKey*"]
    assert "aws:SourceAccount" in s["Condition"]["StringEquals"]


def test_topic_policy_scopes_event_publishers():
    t = _commercial()
    stmts = {s["Sid"]: s for p in _of(t, "AWS::SNS::TopicPolicy") for s in p["PolicyDocument"]["Statement"]}
    ev = stmts["EventBridgeRules"]
    assert ev["Principal"] == {"Service": "events.amazonaws.com"}
    assert "rule/sgea-%s-evt-*" % ENV in json.dumps(ev["Condition"]["ArnLike"]["aws:SourceArn"])
    assert {"Budgets", "CloudWatchAlarms"} <= set(stmts) and "CostAnomalyDetection" not in stmts


def test_token_vault_custom_resource_has_delete_handler():
    t = _commercial()
    (cr,) = _of(t, "Custom::SgeaTokenVaultCmk")
    delete = json.loads(cr["Delete"]) if isinstance(cr["Delete"], str) else cr["Delete"]
    assert delete["action"] == "SetTokenVaultCMKCommand"
    assert delete["parameters"]["kmsConfiguration"]["keyType"] == "ServiceManagedKey"
    # SetTokenVaultCMK is authorized against the identities API path too (sandbox 2026-10-26)
    pol = [p for p in _of(t, "AWS::IAM::ManagedPolicy") if "SetTokenVaultCMK" in json.dumps(p)]
    assert pol and "/identities/set-token-vault-cmk" in json.dumps(pol[0]["PolicyDocument"])


def _run():
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = skipped = 0
    for n, f in fns:
        try:
            f(); passed += 1; print("  PASS  " + n)
        except _Skip as e:
            skipped += 1; print("  SKIP  " + n + "  -> " + str(e))
        except Exception as e:  # noqa: BLE001
            failed += 1; print("  FAIL  " + n + "  -> " + repr(e)[:2000])
    print("\n%d passed, %d failed, %d skipped, %d total" % (passed, failed, skipped, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
