# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the ADR 0003 model-call breaker: the token meter's trip / sweep logic (with an in-memory
ledger and event sink), the shared state-machine definition, and both engines' emitted resources.

Runs two ways:
  - pytest:            pytest -q tests/test_token_breaker.py
  - no dependencies:   python tests/test_token_breaker.py
"""
import copy, importlib.util, json, os, re, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "emitters"))
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402
import derived  # noqa: E402
import terraform_emitter  # noqa: E402

COMMERCIAL = "fedramp-moderate-hipaa.commercial.json"
ACCT = "1" * 12   # placeholder account id (12-digit literals fail the public-tree denylist)
ROLE_ARN = "arn:aws:sts::%s:assumed-role/sgea-sbx-sample-agent/session-1" % ACCT


class _CCF(Exception):
    pass


class _Table:
    """Just enough DynamoDB Table for token_meter: ADD counters, conditional put, query, delete."""
    class meta:
        class client:
            class exceptions:
                ConditionalCheckFailedException = _CCF

    def __init__(self):
        self.items = {}

    def get_item(self, Key, ConsistentRead=False):
        it = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(it)} if it else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ReturnValues=None, **kw):
        it = self.items.setdefault((Key["pk"], Key["sk"]), {"pk": Key["pk"], "sk": Key["sk"]})
        if ":t" in ExpressionAttributeValues:
            it["tokens"] = it.get("tokens", 0) + ExpressionAttributeValues[":t"]
        if ":y" in ExpressionAttributeValues:
            it["released"] = True
        return {"Attributes": {"tokens": it.get("tokens", 0)}}

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeNames=None, ExpressionAttributeValues=None):
        old = self.items.get((Item["pk"], Item["sk"]))
        if ConditionExpression and old and old.get("month") == ExpressionAttributeValues[":m"] \
                and old.get("team") == ExpressionAttributeValues[":t"] and not old.get("released"):
            raise _CCF()
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def query(self, KeyConditionExpression, ExpressionAttributeValues, ExclusiveStartKey=None):
        return {"Items": [dict(v) for (pk, _), v in sorted(self.items.items()) if pk == ExpressionAttributeValues[":p"]]}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None):
        it = self.items.get((Key["pk"], Key["sk"]))
        if ConditionExpression and not (it and it.get("released")):
            raise _CCF()
        self.items.pop((Key["pk"], Key["sk"]), None)


class _Events:
    def __init__(self):
        self.sent = []

    def put_events(self, Entries):
        for e in Entries:
            self.sent.append((e["Source"], e["DetailType"], json.loads(e["Detail"])["roles"]))
        return {"FailedEntryCount": 0, "Entries": [{}]}


def _meter(budget="100", breaker="1"):
    try:
        import boto3  # noqa: F401
    except ImportError:
        return None
    env = {"TOKEN_LEDGER_TABLE": "t", "PER_TEAM_MONTHLY_TOKENS": budget, "TOKEN_BREAKER": breaker,
           "TOKEN_TIMEZONE": "UTC", "AWS_DEFAULT_REGION": "us-east-1"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location("tm_breaker", os.path.join(ROOT, "emitters", "lambda", "token_meter.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
    mod.TABLE, mod._events = _Table(), _Events()
    return mod


def _rec(tokens, team="red", arn=ROLE_ARN):
    return {"input": {"inputTokenCount": tokens}, "output": {"outputTokenCount": 0},
            "requestMetadata": {"sgea_user": "u1", "sgea_team": team}, "identity": {"arn": arn}}


# ---- meter ----------------------------------------------------------------
def test_role_name_from_assumed_role_arn_only():
    m = _meter()
    if not m:
        return
    assert m.role_name(ROLE_ARN) == "sgea-sbx-sample-agent"
    assert m.role_name("arn:aws:iam::%s:user/alice" % ACCT) is None
    assert m.role_name(None) is None


def test_trips_once_when_team_reaches_budget():
    m = _meter()
    if not m:
        return
    m.record(_rec(60))
    assert not m._events.sent                                      # under budget
    m.record(_rec(50))                                             # 110 >= 100
    m.record(_rec(5))                                              # already tripped this month: no second event
    assert m._events.sent == [("sgea.token-meter", "SGEA Token Budget Breaker",
                               [{"role": "sgea-sbx-sample-agent", "team": "red", "action": "attach"}])]
    _, month = m.periods()
    trip = m.TABLE.items[("breaker", "role#sgea-sbx-sample-agent")]
    assert trip["team"] == "red" and trip["month"] == month and not trip.get("released")


def test_no_trip_without_role_or_when_off_or_overridden():
    m = _meter()
    if not m:
        return
    m.record(_rec(200, arn="arn:aws:iam::%s:user/alice" % ACCT))   # not a role session
    assert not m._events.sent
    _, month = m.periods()
    m.TABLE.items[("override", "team#blue#" + month)] = {"pk": "override"}
    m.record(_rec(200, team="blue"))
    assert not m._events.sent
    off = _meter(breaker="0")
    off.record(_rec(200))
    assert not off._events.sent and ("breaker", "role#sgea-sbx-sample-agent") not in off.TABLE.items


def test_sweep_reasserts_then_releases_in_two_steps():
    m = _meter()
    if not m:
        return
    m.record(_rec(150))
    m._events.sent.clear()
    assert m.sweep() == (1, 0)                                     # still over budget: re-attach
    assert m._events.sent[-1][2][0]["action"] == "attach"
    _, month = m.periods()
    m.TABLE.items[("team#red", month)]["tokens"] = 10              # budget raised / usage reset
    assert m.sweep() == (0, 1)                                     # step 1: mark released + detach
    assert m._events.sent[-1][2][0]["action"] == "detach"
    assert m.TABLE.items[("breaker", "role#sgea-sbx-sample-agent")]["released"] is True
    assert m.sweep() == (0, 1)                                     # step 2: detach again + forget
    assert ("breaker", "role#sgea-sbx-sample-agent") not in m.TABLE.items


def test_released_trip_can_trip_again():
    m = _meter()
    if not m:
        return
    m.record(_rec(150))
    _, month = m.periods()
    m.TABLE.items[("breaker", "role#sgea-sbx-sample-agent")]["released"] = True
    m._events.sent.clear()
    m.record(_rec(1))
    assert m._events.sent and m._events.sent[0][2][0]["action"] == "attach"


def test_breaker_failure_never_fails_a_credited_batch():
    m = _meter()
    if not m:
        return

    class Down:
        def put_events(self, Entries):
            raise RuntimeError("events endpoint down")
    m._events = Down()
    assert m.record(_rec(150)) == ("u1", "red", 150)               # credited; trip deferred to the heartbeat
    assert ("breaker", "role#sgea-sbx-sample-agent") in m.TABLE.items


# ---- state machine definition ------------------------------------------------
def test_asl_acts_only_on_ledger_and_tag():
    asl = json.loads(derived.token_breaker_asl())
    assert asl["QueryLanguage"] == "JSONata"
    st = asl["States"]["Roles"]["ItemProcessor"]["States"]
    assert st["Lookup"]["Resource"].endswith("states:::dynamodb:getItem") and st["Lookup"]["Arguments"]["ConsistentRead"] is True
    attach, detach = [c["Condition"] for c in st["Decide"]["Choices"]]
    assert "$exists($states.input.trip)" in attach and "trip.team.S = $states.input.team" in attach and "released" in attach
    assert "$not($exists($states.input.trip))" in detach and "released.BOOL = true" in detach
    assert "Key = 'sgea:team'" in st["GetRole"]["Output"] and "Value = $states.input.team" in st["GetRole"]["Output"]
    assert st["Attach"]["Arguments"]["PolicyArn"] == "${policy_arn}" and st["Detach"]["Arguments"]["PolicyArn"] == "${policy_arn}"
    assert st["Decide"]["Default"] == "Ignored" and st["TeamTagMatches"]["Default"] == "Ignored"


def test_model_enforce_derivation_and_validation():
    r, _ = sgea.resolve(os.path.join(PROFILES, COMMERCIAL))
    assert derived.token_model_enforce(r)
    for mutate in (lambda x: x["token_control"].__setitem__("model_enforce", False),
                   lambda x: x["token_control"].__setitem__("per_team_monthly_tokens", 0),
                   lambda x: x["logging"].__setitem__("model_invocation_logging", False)):
        x = copy.deepcopy(r); mutate(x)
        assert not derived.token_model_enforce(x)
    x = copy.deepcopy(r)
    x["services"]["allow"].remove("stepfunctions")
    assert any("ADR 0003" in e and "stepfunctions" in e for e in sgea.validate(x))


# ---- Terraform ---------------------------------------------------------------
def _tf(mutate=None):
    r, prof = sgea.resolve(os.path.join(PROFILES, COMMERCIAL))
    if mutate:
        r = copy.deepcopy(r); mutate(r)
    d = tempfile.mkdtemp(prefix="sgea-brk-")
    terraform_emitter.emit(r, prof, d, ROOT)
    tc = os.path.join(d, "modules", "token-control")
    return d, open(os.path.join(tc, "main.tf")).read(), open(os.path.join(d, "main.tf")).read()


def test_terraform_breaker_resources_and_least_privilege():
    d, m, root = _tf()
    assert re.search(r"model_enforce\s+= true", root)
    assert os.path.exists(os.path.join(d, "modules", "token-control", "breaker.asl.json"))
    for res in ('aws_iam_policy" "budget_exhausted"', 'aws_sfn_state_machine" "breaker"', 'aws_cloudwatch_event_rule" "breaker"',
                'aws_cloudwatch_event_target" "breaker"', 'aws_cloudwatch_metric_alarm" "breaker_failures"'):
        assert res in m, res
    sp = lambda t: re.sub(r"[ \t]+", " ", t)   # terraform fmt alignment
    m = sp(m)
    assert '"sgea-${var.env}-token-budget-exhausted"' in m and 'Effect = "Deny", Action = ["bedrock:InvokeModel*", "bedrock:RetrieveAndGenerate*"]' in m
    attach = m.split('Sid = "AttachDenyToTeamRoles"')[1].split("},\n")[0]
    assert '"iam:PolicyARN" = local.breaker_policy' in attach and '"aws:ResourceTag/sgea:team" = "false"' in attach
    assert 'Sid = "NeverBreakGlass", Effect = "Deny"' in m
    assert 'include_execution_data = false' in m and "tracing_configuration { enabled = true }" in m
    assert '"events:source" = "sgea.token-meter"' in m and 'TOKEN_BREAKER = var.model_enforce ? "1" : "0"' in m
    assert 'event_pattern = jsonencode({ source = ["sgea.token-meter"], "detail-type" = ["SGEA Token Budget Breaker"] })' in m


def test_terraform_breaker_off_when_disabled():
    _, _, root = _tf(lambda r: r["token_control"].__setitem__("model_enforce", False))
    assert re.search(r"model_enforce\s+= false", root)


def test_states_prefix_allowed_by_service_scp():
    import policy_library
    r, _ = sgea.resolve(os.path.join(PROFILES, COMMERCIAL))
    stmt = json.loads(policy_library.scp_bedrock_surface(r)) if isinstance(policy_library.scp_bedrock_surface(r), str) \
        else policy_library.scp_bedrock_surface(r)
    assert "states:*" in json.dumps(stmt)


def _run():
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1; print("FAIL", name, repr(e))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(_run())
