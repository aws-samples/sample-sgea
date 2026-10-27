# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the derived values, SCP/RCP policy library, both emitters and `sgea check`.

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_emitters_and_check.py

Exercises the shipped baselines/profiles and the built catalogs (catalog/*.json,
from tools/build_catalog.py). No AWS credentials or toolchains needed: the
checker is driven with small synthetic plans / templates.
"""
import json, os, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
CATALOG = os.path.join(ROOT, "catalog")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "emitters"))
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402
import derived, policy_library  # noqa: E402
import terraform_emitter, cdk_emitter  # noqa: E402

ALL_PROFILES = sorted(f for f in os.listdir(PROFILES) if f.endswith(".json") and not f.startswith("_"))


LEDGER_TABLE = "ledger"   # DynamoDB table name the Lambda tests use (not a credential)


def _resolve(name):
    return sgea.resolve(os.path.join(PROFILES, name))


# ---- derived values -------------------------------------------------------
def test_cw_retention_rounds_up_never_down():
    assert derived.cw_retention(365) == 365
    assert derived.cw_retention(1095) == 1096   # IL4 / High
    assert derived.cw_retention(2555) == 2557   # Part 11
    assert derived.cw_retention(91) == 120


def test_replica_region_stays_inside_allowed_regions():
    for name in ALL_PROFILES:
        r, _ = _resolve(name)
        rr = derived.replica_region(r)
        assert rr in r["regions"]["allowed"] and rr != r["regions"]["primary"], name


def test_agentcore_data_events_added_when_service_allowed():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    types = derived.data_event_types(r)
    assert "AWS::S3::Object" in types and "AWS::BedrockAgentCore::Runtime" in types


def test_backup_policy_comes_from_pack_parameters():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    bk = derived.backup_policy(r, ROOT)
    assert bk["retention_days"] == 35          # requiredRetentionDays in the packs
    assert bk["vault_lock"] is True            # HIPAA pack: manual-deletion-disabled


def test_conformance_packs_union_across_composition():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert set(derived.conformance_pack_files(r)) == {"sgea-fedramp-moderate", "sgea-hipaa-security"}


# ---- policy library -------------------------------------------------------
def test_every_profile_renders_every_pack_within_size_limit():
    for name in ALL_PROFILES:
        r, _ = _resolve(name)
        docs = policy_library.render(r, derived.authorized_model_ids(r, ROOT))
        assert set(docs) == set(r["policies"]["scps"] + r["policies"]["rcps"]), name
        for pack, tpl in docs.items():
            assert tpl != "{}" and len(tpl) < policy_library.SCP_MAX_CHARS, (name, pack)


def test_region_lockdown_uses_resolved_regions():
    r, _ = _resolve("dod-il4.govcloud.json")
    doc = policy_library.scp_region_lockdown(r)
    assert doc["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == r["regions"]["allowed"]


def test_inference_profile_scp_pins_geo():
    r, _ = _resolve("dod-il4.govcloud.json")
    nr = policy_library.scp_inference_profile(r)["Statement"][0]["NotResource"]
    assert any("inference-profile/us-gov.*" in x for x in nr) and not any("global." in x for x in nr)


def test_unknown_pack_is_an_error_not_an_empty_policy():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    r["policies"]["scps"] = r["policies"]["scps"] + ["bre-scp-99-made-up"]
    try:
        policy_library.render(r)
    except SystemExit:
        return
    raise AssertionError("unknown pack rendered silently")


# ---- emitters -------------------------------------------------------------
def _emit_both(name):
    r, prof = _resolve(name)
    out = tempfile.mkdtemp(prefix="sgea-test-")
    terraform_emitter.emit(r, prof, os.path.join(out, "terraform"), ROOT)
    cdk_emitter.emit(r, prof, os.path.join(out, "cdk"), ROOT)
    return r, out


def _read_all(d, ext):
    text = ""
    for base, _, files in os.walk(d):
        for f in files:
            if f.endswith(ext):
                text += open(os.path.join(base, f)).read()
    return text


def test_registry_modules_are_pinned_exactly():
    import re
    _, out = _emit_both("dod-il5.govcloud.json")
    hcl = _read_all(os.path.join(out, "terraform"), ".tf")
    calls = re.findall(r'module "[^"]+" \{(.*?)\n\}', hcl, re.S)
    registry = [c for c in calls if re.search(r'source\s*=\s*"terraform-aws-modules/', c)]
    assert len(registry) >= 10
    for c in registry:
        v = re.search(r'version\s*=\s*"([^"]+)"', c)
        assert v and re.fullmatch(r"\d+\.\d+\.\d+", v.group(1)), c[:120]


def test_sample_tenant_matches_runtime_wrapper_interface():
    import re
    _, out = _emit_both("fedramp-moderate-hipaa.commercial.json")
    declared = set(re.findall(r'variable "([^"]+)"', open(os.path.join(
        out, "terraform", "modules", "agentcore-runtime", "variables.tf")).read()))
    tenant = open(os.path.join(ROOT, "examples", "sample-agent", "infra", "main.tf")).read()
    call = re.search(r'module "runtime" \{(.*?)\n\}', tenant, re.S).group(1)
    used = set(re.findall(r"^\s{2}([a-z_]+)\s+=", call, re.M)) - {"source", "depends_on"}
    assert used <= declared, used - declared


def test_sample_agent_and_scripts_compile():
    import py_compile
    files = ["examples/sample-agent/app/agent.py", "examples/sample-agent/tool/handler.py",
             "examples/sample-agent/scripts/e2e_test.py", "tools/sandbox_teardown.py"]
    for f in files:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)


def test_terraform_runtime_is_never_public():
    _, out = _emit_both("fedramp-moderate-hipaa.commercial.json")
    hcl = open(os.path.join(out, "terraform", "modules", "agentcore-runtime", "main.tf")).read()
    assert 'network_mode = "VPC"' in hcl and "PUBLIC" not in hcl


def test_terraform_bakes_resolved_and_derived_values():
    r, out = _emit_both("fedramp-moderate-part11.commercial.json")
    main = open(os.path.join(out, "terraform", "main.tf")).read()
    assert "cloudwatch_retention_days = 2557" in main
    tfvars = json.load(open(os.path.join(out, "terraform", "sgea.auto.tfvars.json")))
    assert "," not in tfvars["default_tags"]["sgea:baselines"]   # commas are invalid in tag values
    assert tfvars["replica_region"] == derived.replica_region(r)


def test_policy_templates_emitted_for_every_pack():
    r, out = _emit_both("fedramp-moderate-hipaa.commercial.json")
    pdir = os.path.join(out, "terraform", "modules", "org-guardrail", "policies")
    bundles = policy_library.bundles(r, derived.authorized_model_ids(r, ROOT))
    assert sorted(f[:-len(".json.tftpl")] for f in os.listdir(pdir)) == sorted(b["name"] for b in bundles)


def test_cdk_config_carries_the_same_derived_values():
    r, out = _emit_both("dod-il4.govcloud.json")
    cfg = json.load(open(os.path.join(out, "cdk", "config.json")))
    assert cfg["_derived"] == json.loads(json.dumps(derived.derive(r, ROOT)))
    assert os.listdir(os.path.join(out, "cdk", "packs"))


def test_cdk_constructs_hold_no_hardcoded_partition():
    _, out = _emit_both("dod-il4.govcloud.json")
    ts = _read_all(os.path.join(out, "cdk", "lib"), ".ts")
    assert "arn:aws:" not in ts and "'PUBLIC'" not in ts


# ---- sgea check -----------------------------------------------------------
def _plan(resources):
    """Minimal `terraform show -json` shape: [(address, type, values, after_unknown)]."""
    return {"planned_values": {"root_module": {"resources": [
        {"address": a, "mode": "managed", "type": t, "values": v} for a, t, v, _ in resources]}},
        "resource_changes": [{"address": a, "change": {"after_unknown": u}} for a, _, _, u in resources]}


def _results(resolved, plan):
    return {cid: (status, detail) for cid, _, status, detail in
            sgea.check(resolved, sgea._plan_resources(plan), CATALOG, "tf")}


def test_check_fails_public_runtime_and_short_retention():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = _results(r, _plan([
        ("rt", "awscc_bedrockagentcore_runtime", {"network_configuration": {"network_mode": "PUBLIC"}}, {}),
        ("lg", "aws_cloudwatch_log_group", {"retention_in_days": 30, "kms_key_id": "k"}, {}),
    ]))
    assert res["SGEA-AC-RT-01"][0] == "FAIL"
    assert res["SGEA-AC-LOG-01"][0] == "FAIL"
    assert res["RULE:cw-loggroup-retention-period-check"][0] == "FAIL"


def test_check_treats_unknown_as_unverified_not_pass():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = _results(r, _plan([("lg", "aws_cloudwatch_log_group", {"retention_in_days": 365, "kms_key_id": None},
                              {"kms_key_id": True})]))
    assert res["SGEA-AC-LOG-02"][0] == "UNVERIFIED"


def test_check_honours_tag_exemptions_and_reports_them():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = _results(r, _plan([
        ("store", "aws_s3_bucket", {"bucket": "s", "tags": {"sgea:role": "log-store"}}, {}),
        ("sink", "aws_s3_bucket", {"bucket": "k", "tags": {"sgea:role": "access-log-sink"}}, {}),
        ("lg", "aws_s3_bucket_logging", {"bucket": "s", "target_bucket": "k"}, {}),
    ]))
    status, detail = res["RULE:s3-bucket-logging-enabled"]
    assert status == "PASS" and "exempt sink" in detail


def test_check_links_sub_resources_per_bucket():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = _results(r, _plan([
        ("a", "aws_s3_bucket", {"bucket": "a", "tags": {}}, {}),
        ("b", "aws_s3_bucket", {"bucket": "b", "tags": {}}, {}),
        ("va", "aws_s3_bucket_versioning", {"bucket": "a", "versioning_configuration": [{"status": "Enabled"}]}, {}),
    ]))
    status, detail = res["RULE:s3-bucket-versioning-enabled"]
    assert status == "FAIL" and "b has no aws_s3_bucket_versioning" in detail


def test_check_cfn_mode_maps_awscc_types_mechanically():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = {cid: s for cid, _, s, _ in sgea.check(r, [
        ("S/Rt", "AWS::BedrockAgentCore::Runtime", {"NetworkConfiguration": {"NetworkMode": "VPC"}, "__ref__": "Rt"}, {})],
        CATALOG, "cfn")}
    assert res["SGEA-AC-RT-01"] == "PASS"


def test_check_requires_every_composed_conformance_pack():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    res = _results(r, _plan([("p", "aws_config_conformance_pack", {"name": "sgea-fedramp-moderate"}, {})]))
    assert res["PACK:FedRAMP-Moderate"][0] == "PASS" and res["PACK:HIPAA-Security"][0] == "FAIL"


# ---- authorization (Services in Scope) ------------------------------------
def test_agentcore_not_authorized_for_il4_is_flagged():
    r, _ = _resolve("dod-il4.govcloud.json")
    errs = [e for e in sgea.validate(r, PROFILES) if e.startswith(sgea.AUTH_PREFIX)]
    assert any("bedrock-agentcore" in e and "dod-il4" in e for e in errs), errs


def test_commercial_profiles_are_fully_authorized():
    for name in ["fedramp-moderate-hipaa.commercial.json", "fedramp-low.commercial.json",
                 "fedramp-moderate-part11.commercial.json"]:
        r, _ = _resolve(name)
        assert not [e for e in sgea.validate(r, PROFILES) if e.startswith(sgea.AUTH_PREFIX)], name


# ---- regions --------------------------------------------------------------
def test_region_outside_authorization_boundary_is_flagged():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    r["regions"]["allowed"] = r["regions"]["allowed"] + ["eu-west-1"]
    errs = [e for e in sgea.validate(r, PROFILES) if e.startswith(sgea.REGION_PREFIX)]
    assert any("East/West" in e and "eu-west-1" in e for e in errs), errs


def test_govcloud_baseline_must_stay_in_govcloud():
    r, _ = _resolve("fedramp-high.govcloud.json")
    r["regions"]["allowed"] = ["us-gov-west-1", "us-east-1"]
    errs = [e for e in sgea.validate(r, PROFILES) if e.startswith(sgea.REGION_PREFIX)]
    assert any("GovCloud" in e and "us-east-1" in e for e in errs), errs


def test_govcloud_uses_interceptor_instead_of_policy_engine():
    r, _ = _resolve("fedramp-high.govcloud.json")
    assert any("interceptor" in n and "PolicyEngine" in n for n in sgea.region_notes(r, ROOT))
    assert derived.policy_engine_available(r, ROOT) is False
    _, out = _emit_both("fedramp-high.govcloud.json")
    main = open(os.path.join(out, "terraform", "main.tf")).read()
    import re
    assert re.search(r"tool_policy_interceptor\s+= true", main)
    r2, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert derived.policy_engine_available(r2, ROOT) is True


def test_agentcore_secondary_region_gap_is_a_note():
    r, _ = _resolve("fedramp-high.govcloud.json")
    assert any("bedrock-agentcore" in n and "us-gov-east-1" in n for n in sgea.region_notes(r, ROOT))


def test_il4_authorized_models_are_a_subset_of_high():
    hi, _ = _resolve("fedramp-high.govcloud.json")
    il4, _ = _resolve("dod-il4.govcloud.json")
    a, b = set(derived.authorized_models(hi, ROOT)), set(derived.authorized_models(il4, ROOT))
    assert b and b < a


# ---- tool-path interceptor (GovCloud policy-engine stand-in) ---------------
def _interceptor(rules):
    import importlib.util
    os.environ["TOOL_POLICY"] = json.dumps(rules)
    spec = importlib.util.spec_from_file_location("tpi", os.path.join(ROOT, "emitters", "lambda", "tool_policy_interceptor.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _call(mod, tool, claims=None, method="tools/call"):
    import base64
    tok = "x." + base64.urlsafe_b64encode(json.dumps(claims or {}).encode()).decode().rstrip("=") + ".y"
    ev = {"mcp": {"gatewayRequest": {"headers": {"Authorization": "Bearer " + tok},
                                     "body": {"jsonrpc": "2.0", "id": 7, "method": method, "params": {"name": tool}}}}}
    return mod.handler(ev, None)


def test_interceptor_default_denies_every_tool_call():
    out = _call(_interceptor([]), "search___query")
    assert out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == -32003


def test_interceptor_allows_by_glob_and_deny_overrides():
    mod = _interceptor([{"effect": "allow", "tools": ["search___*"]},
                        {"effect": "deny", "tools": ["search___admin*"]}])
    assert "transformedGatewayResponse" not in _call(mod, "search___query")["mcp"]
    assert "transformedGatewayResponse" in _call(mod, "search___admin_reset")["mcp"]


def test_interceptor_claim_scoping_and_passthrough():
    mod = _interceptor([{"effect": "allow", "tools": ["*"], "claim": "cognito:groups", "values": ["analysts"]}])
    assert "transformedGatewayResponse" not in _call(mod, "t", {"cognito:groups": ["analysts"]})["mcp"]
    assert "transformedGatewayResponse" in _call(mod, "t", {"cognito:groups": ["guests"]})["mcp"]
    assert "transformedGatewayResponse" not in _call(mod, "t", method="tools/list")["mcp"]


def test_contextual_pii_anonymized_hard_identifiers_blocked():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert r["guardrails"]["pii"]["contextual_action"] == "ANONYMIZE" and r["guardrails"]["pii"]["action"] == "BLOCK"
    d = tempfile.mkdtemp()
    terraform_emitter.emit(r, None, d, ROOT)
    main = open(os.path.join(d, "modules", "bedrock-guardrail", "main.tf")).read()
    assert "contains(local.contextual_entities, t) ? local.ctx_action : local.pii_action" in main
    from guardrail_map import CONTEXTUAL_ENTITIES
    assert "ADDRESS" in CONTEXTUAL_ENTITIES and "US_SOCIAL_SECURITY_NUMBER" not in CONTEXTUAL_ENTITIES


# ---- token budgets (interceptor) + meter -------------------------------------
class _FakeTable:
    def __init__(self, items=None, fail=False):
        self.items, self.fail, self.updates = dict(items or {}), fail, []

    def get_item(self, Key, ConsistentRead=False):
        if self.fail:
            raise RuntimeError("ledger down")
        it = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": it} if it else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues):
        self.updates.append((Key["pk"], Key["sk"], ExpressionAttributeValues[":t"]))

    def put_item(self, Item):
        self.items[(Item["pk"], Item["sk"])] = Item


def _budget_interceptor(table, enforce_tool_policy="false"):
    env = {"TOOL_POLICY_ENFORCE": enforce_tool_policy, "TOKEN_LEDGER_TABLE": LEDGER_TABLE, "PER_USER_DAILY_TOKENS": "100",
           "PER_TEAM_MONTHLY_TOKENS": "1000", "FAIL_CLOSED_HOURS": "4", "TOKEN_TIMEZONE": "UTC"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        mod = _interceptor([])
    finally:
        for k, v in old.items():
            os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
    mod._table = table
    return mod


def _denied(out):
    return "transformedGatewayResponse" in out["mcp"]


def test_token_budget_allows_within_and_denies_past_budget():
    import time
    t = _FakeTable({("meter", "heartbeat"): {"at": time.time()}})
    mod = _budget_interceptor(t)
    day, month = mod._periods()
    assert not _denied(_call(mod, "t", {"sub": "u1"}))
    t.items[("user#u1", day)] = {"tokens": 100}
    assert _denied(_call(mod, "t", {"sub": "u1"}))
    t.items[("team#red", month)] = {"tokens": 1000}
    assert _denied(_call(mod, "t", {"sub": "u2", "cognito:groups": ["red"]}))
    assert not _denied(_call(mod, "t", {"sub": "u2", "cognito:groups": ["blue"]}))


def test_token_budget_fails_closed():
    import time
    assert _denied(_call(_budget_interceptor(_FakeTable(fail=True)), "t", {"sub": "u"}))      # ledger down
    assert _denied(_call(_budget_interceptor(_FakeTable({("meter", "heartbeat"): {"at": time.time() - 5 * 3600}})),
                         "t", {"sub": "u"}))                                                     # stale meter
    assert _denied(_call(_budget_interceptor(_FakeTable({("meter", "heartbeat"): {"at": time.time()}})), "t", {}))  # no identity


def test_token_budget_runs_after_tool_policy():
    import time
    mod = _budget_interceptor(_FakeTable({("meter", "heartbeat"): {"at": time.time()}}), enforce_tool_policy="true")
    out = _call(mod, "t", {"sub": "u"})          # TOOL_POLICY [] => default deny before the budget
    assert "tool-policy" in out["mcp"]["transformedGatewayResponse"]["body"]["error"]["message"]


def test_token_meter_credits_user_and_team():
    import importlib.util
    os.environ["TOKEN_LEDGER_TABLE"] = LEDGER_TABLE
    try:
        import boto3  # noqa: F401
    except ImportError:
        return
    spec = importlib.util.spec_from_file_location("tm", os.path.join(ROOT, "emitters", "lambda", "token_meter.py"))
    mod = importlib.util.module_from_spec(spec)
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    spec.loader.exec_module(mod)
    mod.TABLE = t = _FakeTable()
    rec = {"input": {"inputTokenCount": 30}, "output": {"outputTokenCount": 12},
           "requestMetadata": {"sgea_user": "u1", "sgea_team": "red"}, "identity": {"arn": "arn:x"}}
    assert mod.record(rec) == ("u1", "red", 42)
    day, month = mod.periods()
    assert ("user#u1", day, 42) in t.updates and ("team#red", month, 42) in t.updates
    assert mod.record({"input": {}, "output": {}}) is None


def test_token_control_emitted_when_enabled():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    import tempfile
    d = tempfile.mkdtemp()
    terraform_emitter.emit(r, None, d, ROOT)
    main = open(os.path.join(d, "main.tf")).read()
    import re
    assert re.search(r"token_budget_enforce\s+= true", main) and re.search(r"\bmeter\s+= true", main)
    assert os.path.exists(os.path.join(d, "modules", "token-control", "token_meter.zip"))


# ---- control coverage: every pack rule is checked or carries a recorded disposition ----
def test_every_pack_rule_is_checked_or_dispositioned():
    import glob, yaml
    disp = yaml.safe_load(open(os.path.join(ROOT, "sources", "inferred", "rule-dispositions.yaml")))["dispositions"]
    pc = json.load(open(os.path.join(ROOT, "sources", "inferred", "config-rule-plan-checks.json")))
    assert set(pc["rules"]) == set(pc["cfn_rules"])                        # TF and CDK checks in lockstep
    assert not set(disp) & set(pc["rules"])                                 # never both
    assert not [n for n, d in disp.items() if d["disposition"] == "implement"], "open implement gaps"
    for f in glob.glob(os.path.join(ROOT, "catalog", "*.json")):
        if os.path.basename(f).startswith("_"):
            continue
        cat = json.load(open(f))
        rules = {r["config_rule"] for lst in cat["services"].values() for r in lst}
        assert rules == set(cat["coverage"]), os.path.basename(f)
        assert rules <= set(pc["rules"]) | set(disp), os.path.basename(f)


def test_iam_policy_content_operators():
    import sgea as sg
    admin = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    full = {"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::b"}]}
    kms_all = {"Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*"}]}
    kms_one = {"Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "arn:aws:kms:us-east-1:1:key/abc"}]}
    m = lambda doc, op, t=None: sg._meets(doc, False, {"op": op}, t)
    assert not m(admin, "iam_no_admin") and m(full, "iam_no_admin")
    assert not m(full, "iam_no_full_access") and m(kms_one, "iam_no_full_access")
    assert not m(kms_all, "iam_no_blocked_kms", "kms:Decrypt,kms:ReEncryptFrom")
    assert m(kms_one, "iam_no_blocked_kms", "kms:*, kms:Decrypt, kms:ReEncrypt*")
    assert m(json.dumps(kms_one), "iam_no_blocked_kms")                     # Terraform plans the JSON string
    assert m([], "empty") and not m([{"from_port": 0}], "empty")


def test_account_baseline_from_pack_parameters():
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    ab = derived.account_baseline(r, ROOT)
    assert ab["password_policy"]["minimum_password_length"] >= 14 and ab["password_policy"]["max_password_age"] <= 90
    assert ab["lambda_reserved_concurrency"] == 500 and ab["alarm_insufficient_data_action"] is True
    assert ab["ebs_encryption_by_default"] and ab["s3_account_public_access_block"] and ab["default_security_group_closed"]


def test_manual_steps_list_the_lambda_quota_request():
    import manual_steps
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    md = manual_steps.render(r, ROOT, ["terraform", "cdk"])
    assert "at least 1100" in md and "L-B99A9384" in md and "Business Associate Addendum" in md
    r4, _ = _resolve("dod-il4.govcloud.json")             # pack sets no ConcurrencyLimitLow: no quota step
    md4 = manual_steps.render(r4, ROOT, ["terraform"])
    assert "L-B99A9384" not in md4 and "GovCloud" in md4 and "SCCA" in md4


def test_known_findings_reach_the_affected_profiles():
    import manual_steps, yaml
    kf = yaml.safe_load(open(os.path.join(ROOT, "sources", "inferred", "known-findings.yaml")))["findings"]
    assert all(f["owner"] in ("enclave", "tenant") and f["status"] in ("open", "fixed") for f in kf)
    assert all(f["customer_action"] and f["impact"] for f in kf if f["status"] == "open")
    assert all(f["fix"] and f["verified"] for f in kf if f["status"] == "fixed")
    r, _ = _resolve("fedramp-moderate-hitrust.commercial.json")
    md = manual_steps.render(r, ROOT, ["terraform"])
    assert "SGEA-KF-02" in md and "SGEA-KF-01" not in md      # KF-01 fixed: no customer action left
    r, _ = _resolve("dod-il4.govcloud.json")                 # IL4 packs have no lambda-concurrency-check
    assert "SGEA-KF-02" not in manual_steps.render(r, ROOT, ["terraform"])


# ---- packaging: an installed CLI must carry everything the emitters read at runtime ----
def test_package_data_covers_emitter_runtime_files():
    import glob, re
    py = open(os.path.join(ROOT, "pyproject.toml")).read()
    assert re.search(r'dependencies = \["pyyaml==', py)                    # export imports yaml (exact pin)
    globs = re.findall(r'"((?:lambda|cdk_app)[^"]*)"', py.split("[tool.setuptools.package-data]", 1)[1])
    covered = {f for g in globs for f in glob.glob(os.path.join(ROOT, "emitters", g))}
    needed = {f for f in glob.glob(os.path.join(ROOT, "emitters", "lambda", "*.py"))} | \
             {f for f in glob.glob(os.path.join(ROOT, "emitters", "cdk_app", "**", "*"), recursive=True) if os.path.isfile(f)}
    assert needed <= covered, sorted(needed - covered)


def test_emitters_load_from_one_place():
    tf, cdk, ms, ops = sgea._load_emitters()
    dirs = {os.path.dirname(os.path.abspath(m.__file__)) for m in (tf, cdk, ms, ops)}
    assert len(dirs) == 1, dirs                                            # never a mix of checkout + installed copy


def test_plan_linking_with_unknown_bucket_names_stays_per_module():
    """Unknown link attributes (values deferred at plan) must not link a check to every bucket."""
    import sgea as sg
    r, _ = _resolve("fedramp-moderate-hitrust.commercial.json")
    B = "module.enclave_logging.module.%s.module.bucket.aws_s3_bucket.this[0]"
    N = "module.enclave_logging.module.%s.module.notification.aws_s3_bucket_notification.this[0]"
    res = [(B % "log_store", "aws_s3_bucket", {"bucket": None, "tags": {"sgea:role": "log-store"}}, {"bucket": True}),
           (N % "log_store", "aws_s3_bucket_notification", {"bucket": None, "topic": [{"id": "removals"}]}, {"bucket": True}),
           (B % "replica", "aws_s3_bucket", {"bucket": None, "tags": {"sgea:region": "replica"}}, {"bucket": True}),
           (N % "replica", "aws_s3_bucket_notification", {"bucket": None, "topic": []}, {"bucket": True})]
    out = {cid: (st, d) for cid, _, st, d in sg.check(r, res, os.path.join(ROOT, "catalog"), "tf")}
    assert out["RULE:s3-event-notifications-enabled"][0] == "PASS", out["RULE:s3-event-notifications-enabled"]


# ---- model allow-list + SCP bundling ----------------------------------------
def test_il4_model_allowlist_is_exact():
    r, _ = _resolve("dod-il4.govcloud.json")
    ids = derived.authorized_model_ids(r, ROOT)
    assert "anthropic.claude-sonnet-5" in ids and "anthropic.claude-sonnet-5-5" not in ids
    doc = policy_library.scp_model_allowlist(r, ids)
    nr = doc["Statement"][0]["NotResource"]
    assert not any(x.endswith("claude-sonnet-5*") for x in nr)       # no prefix wildcard across models


def test_policy_bundles_respect_aws_attachment_and_size_limits():
    for name in ALL_PROFILES:
        r, _ = _resolve(name)
        bs = policy_library.bundles(r, derived.authorized_model_ids(r, ROOT))
        for t in ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"):
            assert len([b for b in bs if b["type"] == t]) <= policy_library.MAX_ATTACHED, (name, t)
        assert all(len(policy_library._sample(b["template"])) <= policy_library.SCP_MAX_CHARS for b in bs), name
        assert sorted(p for b in bs for p in b["packs"]) == sorted(r["policies"]["scps"] + r["policies"]["rcps"]), name


# ---- DoD IL2 / IL5 ------------------------------------------------------------
def test_il2_is_commercial_and_authorized():
    r, _ = _resolve("dod-il2.commercial.json")
    assert r["partition"] == "aws" and not derived.scca_required(r)
    assert not [e for e in sgea.validate(r, PROFILES) if e.startswith(sgea.DOWNGRADABLE)]


def test_il5_requires_scca_and_flags_agentcore():
    r, _ = _resolve("dod-il5.govcloud.json")
    assert r["partition"] == "aws-us-gov" and derived.scca_required(r)
    assert any("bedrock-agentcore" in e and "dod-il5" in e for e in sgea.validate(r, PROFILES))


# ---- check grammar ------------------------------------------------------------
def test_applies_when_grammar():
    r = {"partition": "aws-us-gov", "baselines": ["dod-il5"], "guardrails": {"levels": ["gateway_tool_path"]}}
    assert sgea._applies("baselines contains dod-il4|dod-il5", r)
    assert not sgea._applies("guardrails.levels contains gateway_tool_path && partition != aws-us-gov", r)
    assert sgea._applies("partition == aws-us-gov", r)


def test_any_of_accepts_interceptor_instead_of_policy_engine():
    r, _ = _resolve("fedramp-high.govcloud.json")
    res = _results(r, _plan([("gw", "awscc_bedrockagentcore_gateway",
                              {"policy_engine_configuration": None, "interceptor_configurations": [{"x": 1}]}, {})]))
    assert res["SGEA-AC-GW-03"][0] == "PASS"
    res = _results(r, _plan([("gw", "awscc_bedrockagentcore_gateway",
                              {"policy_engine_configuration": None, "interceptor_configurations": None}, {})]))
    assert res["SGEA-AC-GW-03"][0] == "FAIL"


# ---- catalog builder ------------------------------------------------------
def test_catalog_builder_rejects_unknown_provider_attribute():
    import shutil
    if not os.path.isdir(os.path.join(ROOT, "sources", "artifact")):   # AWS Artifact inputs: NDA, never committed (CI)
        try:
            import pytest
        except ImportError:
            return
        pytest.skip("needs sources/artifact/ (AWS Artifact, NDA; not in the repository)")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_catalog
    tmp = tempfile.mkdtemp(prefix="sgea-cat-")
    shutil.copytree(os.path.join(ROOT, "sources"), os.path.join(tmp, "sources"))
    path = os.path.join(tmp, "sources", "inferred", "service-controls.yaml")
    text = open(path).read().replace("attribute: network_configuration.network_mode\n",
                                     "attribute: network_configuration.bogus_mode\n", 1)
    open(path, "w").write(text)
    guide = build_catalog.load_guide(os.path.join(tmp, "sources"))
    try:
        build_catalog.load_inferred(os.path.join(tmp, "sources"), guide)
    except SystemExit as e:
        assert "bogus_mode" in str(e)
        return
    raise AssertionError("unknown attribute accepted")


# ---- standalone runner (no pytest needed) -------------------------------
# ---- OPERATIONS.md (day-2 runbook + ConMon calendar) ----------------------
def test_export_writes_operations_next_to_manual_steps():
    out = tempfile.mkdtemp(prefix="sgea-ops-")
    rc = sgea.main(["export", "--profile", os.path.join(PROFILES, "fedramp-moderate-hitrust.commercial.json"),
                    "--out", out, "--emit", "terraform"])
    d = os.path.join(out, "fedramp-moderate-hipaa-hitrust-commercial")
    assert rc == 0 and os.path.isfile(os.path.join(d, "MANUAL-STEPS.md")), os.listdir(d)
    md = open(os.path.join(d, "OPERATIONS.md")).read()
    assert md.startswith("# Operations — fedramp-moderate-hipaa-hitrust-commercial")
    assert "sgea-<env>-security-alarms" in md and "sgea-<env>-log-store-events" in md
    assert "docs/operations/access-review.md" in md and "--engine terraform" in md and "--engine cdk" not in md


def test_operations_values_come_from_the_profile():
    import operations, manual_steps
    for name in ("fedramp-moderate-part11.commercial.json", "dod-il4.govcloud.json"):
        r, _ = _resolve(name)
        md = operations.render(r, ROOT, ["terraform"])
        assert "keeps **%d days**" % derived.log_retention_days(r, ROOT) in md, name
        assert "retention %d days" % derived.backup_policy(r, ROOT)["retention_days"] in md, name
        assert ("arn:%s:sns:%s:<account>:" % (r["partition"], r["regions"]["primary"])) in md, name
        assert "USD %.2f / month" % sum(v for _, v in manual_steps.cost_estimate(r)) in md, name
        for p in derived.conformance_pack_files(r):
            assert "--conformance-pack-name %s " % p in md, (name, p)
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")       # quota from the same logic as MANUAL-STEPS
    assert "at least **1100**" in operations.render(r, ROOT, ["terraform"])
    r4, _ = _resolve("dod-il4.govcloud.json")
    assert "Lambda concurrency headroom" not in operations.render(r4, ROOT, ["terraform"])


def test_operations_aurora_restore_only_when_aurora_is_allowed():
    import copy, operations
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    md = operations.render(r, ROOT, ["terraform"])
    assert "| Aurora PostgreSQL cluster | `sgea-<env>-vector` |" in md and "| Token ledger (DynamoDB) |" in md
    r2 = copy.deepcopy(r)
    r2["services"]["allow"].remove("aurora-postgresql")
    r2["vector_store"] = "none"
    md2 = operations.render(r2, ROOT, ["terraform"])
    assert "Aurora PostgreSQL cluster" not in md2 and "| Token ledger (DynamoDB) |" in md2


def test_operations_conmon_rows_only_for_the_profile_baselines():
    import operations
    r, _ = _resolve("fedramp-moderate-hitrust.commercial.json")
    md = operations.render(r, ROOT, ["terraform"])
    cal = md.split("## 4. Continuous-monitoring evidence calendar", 1)[1].split("## 5.", 1)[0]
    assert "FedRAMP ConMon" in cal and "HIPAA risk analysis" in cal and "HITRUST" in cal
    assert "DoD" not in cal and "Part 11" not in cal
    assert "Process control `annual-risk-assessment-performed`" in cal
    r, _ = _resolve("dod-il4.govcloud.json")
    cal = operations.render(r, ROOT, ["terraform"]).split("## 4.", 1)[1].split("## 5.", 1)[0]
    assert "DoD CC SRG ConMon" in cal and "SCCA" in cal and "HIPAA" not in cal and "HITRUST" not in cal
    assert "FedRAMP" not in cal
    r, _ = _resolve("fedramp-low.commercial.json")
    cal = operations.render(r, ROOT, ["terraform"]).split("## 4.", 1)[1].split("## 5.", 1)[0]
    assert "FedRAMP ConMon" in cal and "IR-3" not in cal and "HIPAA" not in cal
    for row in [l for l in cal.splitlines() if l.startswith("| ") and not l.startswith("| Cadence")]:
        assert set(row.rsplit("|", 2)[1].strip().split(", ")) <= set(r["baselines"]), row


def test_operations_alarm_names_match_the_emitters():
    import re, copy, operations
    r, out = _emit_both("fedramp-moderate-hipaa.commercial.json")
    tf = _read_all(os.path.join(out, "terraform"), ".tf")
    import terraform_emitter as te
    raw = re.findall(r'alarm_name\s*=\s*"([^"]+)"', tf)
    ct = ["sgea-${var.env}-ct-%s" % n for n, _ in te.CT_FILTERS] + ["sgea-${var.env}-ct-break-glass-assumed"]
    raw = [x for x in raw if x != "sgea-${var.env}-ct-${each.key}"] + (ct if "sgea-${var.env}-ct-${each.key}" in raw else [])
    emitted = {n.replace("${local.interceptor_name}", "sgea-${var.env}-tool-policy").replace("${var.env}", "<env>") for n in raw}
    names = {a[0] for a in operations.alarms(r, ROOT)}
    assert names == emitted, (names, emitted)
    cdk_src = _read_all(os.path.join(ROOT, "emitters", "cdk_app", "lib"), ".ts")
    assert "`${fname}-errors`" in cdk_src and "`${fname}-silent`" in cdk_src
    assert "sgea-${i.env}-tool-policy" in cdk_src and "sgea-${i.env}-token-meter" in cdk_src
    md = operations.render(r, ROOT, ["terraform"])
    assert all("`%s`" % n in md for n in names)
    off = copy.deepcopy(r)                                  # no token control, policy engine available: no alarms
    off["token_control"]["enabled"] = False
    assert {a[0] for a in operations.alarms(off, ROOT)} == {a[0] for a in operations.monitoring_alarms(off)}
    assert "sgea-<env>-token-meter" not in operations.render(off, ROOT, ["terraform"])
    assert "Token budgets" not in operations.render(off, ROOT, ["terraform"])


def test_operations_backup_schedule_matches_the_emitters():
    import operations
    r, out = _emit_both("fedramp-moderate-hipaa.commercial.json")
    assert 'schedule          = "%s"' % operations.BACKUP_SCHEDULE in _read_all(os.path.join(out, "terraform"), ".tf")
    cdk_src = open(os.path.join(ROOT, "emitters", "cdk_app", "lib", "constructs", "enclave-backup.ts")).read()
    assert "events.Schedule.cron({ minute: '0', hour: '5' })" in cdk_src      # = cron(0 5 * * ? *)


def test_operations_has_no_account_ids_or_artifact_text():
    import re, operations
    for name in ALL_PROFILES:
        r, _ = _resolve(name)
        md = operations.render(r, ROOT, ["terraform", "cdk"])
        assert not re.search(r"\b\d{12}\b", md), name
        assert "_nda" not in md and "sources/artifact" not in md and "aws_documents" not in md, name


def _run():
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for n, f in fns:
        try:
            f(); passed += 1; print("  PASS  " + n)
        except Exception as e:  # noqa: BLE001
            failed += 1; print("  FAIL  " + n + "  -> " + repr(e))
    print("\n%d passed, %d failed, %d total" % (passed, failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())


def test_cost_estimate_counts_the_emitted_endpoints():
    import manual_steps
    from derived import endpoint_services
    r, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    lines = dict(manual_steps.cost_estimate(r, azs=2))
    n = len(endpoint_services(r))
    assert lines["Interface VPC endpoints (%d services x 2 AZs)" % n] == n * 2 * manual_steps.VPCE_HOUR * manual_steps.HOURS_PER_MONTH
    assert "## Running cost estimate (enclave only)" in manual_steps.render(r, ROOT, ["terraform"])


def test_mit0_headers_on_sources_and_generated_iac():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import license_headers
    try:
        files = license_headers.tracked_sources()
    except Exception:   # not a git checkout
        files = []
    missing = [f for f in files if not license_headers.has_header(open(os.path.join(ROOT, f)).read())]
    assert not missing, missing
    out = tempfile.mkdtemp(prefix="sgea-hdr-")
    sgea.main(["export", "--profile", os.path.join(PROFILES, "fedramp-moderate-hipaa.commercial.json"), "--out", out])
    gen = [os.path.join(d, f) for d, _, fs in os.walk(out) for f in fs if f.endswith((".tf", ".ts", ".py"))]
    assert gen and all(license_headers.has_header(open(p).read()) for p in gen), [p for p in gen if not license_headers.has_header(open(p).read())][:5]
