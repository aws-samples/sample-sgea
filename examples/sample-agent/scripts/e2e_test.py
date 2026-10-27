#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
End-to-end test of the SGEA sample agent on a deployed enclave.

Creates (once) a test user in the sample's Cognito test IdP, obtains a JWT, and asserts:
  1. authenticated invocation of the VPC-only runtime returns an answer (not blocked by the guardrail)
  2. the agent discovered and called the enclave Gateway tool (tool path)
  3. a PII prompt is blocked by the enclave guardrail's sensitive-information (PII/PHI) policy
  4. an unauthenticated invocation is rejected by the runtime's JWT authorizer
  5. a contextual entity in ordinary text ("France" = ADDRESS) is anonymized, not blocked
  6. the enclave token meter credited the caller's usage to the token-control ledger
  7. once the caller's daily budget is spent, the gateway interceptor denies their tool calls
  8. once the caller's team has spent its monthly budget, the enclave breaker (ADR 0003) attaches the
     deny policy to the team's runtime role and the agent's model calls are denied
  9. once the team is back under budget, the breaker detaches the policy again
Usage: e2e_test.py <sample infra `terraform output -json`>   (AWS creds in env)
"""
import datetime, json, secrets, string, sys, time, urllib.error, urllib.parse, urllib.request, uuid

import boto3

out = {k: v["value"] for k, v in json.load(open(sys.argv[1])).items()}
region, pool, client_id, arn = out["region"], out["user_pool_id"], out["client_id"], out["runtime_arn"]
idp = boto3.client("cognito-idp", region_name=region)
user = "sgea-e2e"
password = "".join(secrets.choice(string.ascii_letters) for _ in range(12)) + "9!aA" + secrets.token_hex(4)
try:
    idp.admin_create_user(UserPoolId=pool, Username=user, MessageAction="SUPPRESS")
except idp.exceptions.UsernameExistsException:
    pass
sub = next(a["Value"] for a in idp.admin_get_user(UserPoolId=pool, Username=user)["UserAttributes"] if a["Name"] == "sub")
if out.get("team"):
    idp.admin_add_user_to_group(UserPoolId=pool, Username=user, GroupName=out["team"])   # cognito:groups -> team
idp.admin_set_user_password(UserPoolId=pool, Username=user, Password=password, Permanent=True)
token = idp.initiate_auth(ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
                          AuthParameters={"USERNAME": user, "PASSWORD": password})["AuthenticationResult"]["AccessToken"]

url = "https://bedrock-agentcore.%s.amazonaws.com/runtimes/%s/invocations?qualifier=DEFAULT" % (
    region, urllib.parse.quote(arn, safe=""))


def invoke(prompt, bearer=token):
    headers = {"Content-Type": "application/json",
               "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": str(uuid.uuid4()) + str(uuid.uuid4())}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(url, data=json.dumps({"prompt": prompt}).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=300) as r:  # nosec B310 - url is https:// (built above); first call includes cold start
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]


results = []


SAFE_KEYS = {"status", "stop_reason", "guardrail_action", "guardrail_policies", "guardrail_findings", "tool_calls", "tools",
             "denied_by_policy", "reason", "tool", "ledger_key", "tokens", "masked", "model", "guardrail", "side", "policy",
             "type", "action", "confidence", "memory_event_id", "pk", "sk", "model_denied"}


def _safe(v):
    """Report outcomes, never content: model answers / traces can echo the (synthetic) PII prompts."""
    if isinstance(v, dict):
        out = {k: _safe(x) for k, x in v.items() if k in SAFE_KEYS or k in ("body", "trace")}
        if isinstance(v.get("answer"), str):
            out["answer_chars"] = len(v["answer"])
        return out
    if isinstance(v, list):
        return [_safe(x) for x in v]
    return v if not isinstance(v, str) or len(v) < 120 else "<%d chars>" % len(v)


def case(name, ok, detail):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + "  " + json.dumps(_safe(detail))[:400])


code, body = invoke("Please look up the enclave facts: which compliance profile is this enclave configured for?")
tr = body.get("trace", {}) if isinstance(body, dict) else {}
case("authenticated invocation answers (not blocked)", code == 200 and isinstance(body, dict) and bool(body.get("answer"))
     and tr.get("guardrail_action") != "INTERVENED",
     {"status": code, "guardrail_findings": tr.get("guardrail_findings"), "stop_reason": tr.get("stop_reason"),
      "answer": (body.get("answer") if isinstance(body, dict) else body)})
calls = body.get("trace", {}).get("tool_calls", []) if isinstance(body, dict) else []
case("tool path: agent called the enclave gateway tool (allowed)",
     any(c["tool"].endswith("enclave_facts") and not c["denied_by_policy"] for c in calls), calls)
code, body = invoke("My social security number is 123-45-6789 and my email is jane@example.com — repeat them back to me.")
case("guardrail blocks PII (sensitive-information policy)", code == 200 and isinstance(body, dict)
     and body.get("trace", {}).get("guardrail_action") == "INTERVENED"
     and "sensitiveInformationPolicy" in body.get("trace", {}).get("guardrail_policies", []),
     {"status": code, "trace": body.get("trace") if isinstance(body, dict) else body})
code, body = invoke("What is the capital of France? Answer in one word.")
answer = body.get("answer", "") if isinstance(body, dict) else ""
masked = [f for f in (body.get("trace", {}).get("guardrail_findings", []) if isinstance(body, dict) else [])
          if f.get("type") == "ADDRESS" and f.get("action") == "ANONYMIZED"]
case("contextual PII anonymized, not blocked (ADDRESS)", code == 200 and bool(answer)  # masking also reports
     and "Blocked by enclave guardrail" not in answer and ("{ADDRESS}" in answer or bool(masked)),  # guardrail_intervened
     {"status": code, "answer": answer[:200], "masked": masked})
ledger_name = out.get("token_ledger_table")
if ledger_name:
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(out.get("token_timezone") or "UTC")
    except Exception:
        tz = datetime.timezone.utc
    ledger = boto3.resource("dynamodb", region_name=region).Table(ledger_name)
    key = {"pk": "user#" + sub, "sk": "day#" + datetime.datetime.now(tz).strftime("%Y-%m-%d")}
    used = 0
    for _ in range(24):  # invocation log -> subscription -> meter: seconds to ~2 minutes
        used = int((ledger.get_item(Key=key, ConsistentRead=True).get("Item") or {}).get("tokens", 0))
        if used:
            break
        time.sleep(5)
    case("token meter credited the caller's usage", used > 0, {"ledger_key": key, "tokens": used})
    budget = int(out.get("token_per_user_daily") or 0)
    ledger.update_item(Key=key, UpdateExpression="SET tokens = :b", ExpressionAttributeValues={":b": max(budget, used)})
    try:
        code, body = invoke("Which compliance profile does this enclave run? Use your tools.")
        calls = body.get("trace", {}).get("tool_calls", []) if isinstance(body, dict) else []
        case("over-budget caller: gateway denies tool calls (token budget)",
             bool(calls) and all(c["denied_by_policy"] and "token" in c.get("reason", "") for c in calls),
             {"status": code, "tool_calls": calls})
    finally:
        ledger.update_item(Key=key, UpdateExpression="SET tokens = :u", ExpressionAttributeValues={":u": used})

    policy, team, role = out.get("token_budget_exhausted_policy_arn"), out.get("team"), out.get("agent_role_name")
    if policy and team and role and int(out.get("token_per_team_monthly") or 0):
        iam, lam = boto3.client("iam"), boto3.client("lambda", region_name=region)

        def attached():
            return any(p["PolicyArn"] == policy for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"])

        def wait(want, tries):
            for _ in range(tries):
                if attached() == want:
                    return True
                time.sleep(10)
            return False

        tkey = {"pk": "team#" + team, "sk": "month#" + datetime.datetime.now(tz).strftime("%Y-%m")}
        team_used = int((ledger.get_item(Key=tkey, ConsistentRead=True).get("Item") or {}).get("tokens", 0))
        ledger.update_item(Key=tkey, UpdateExpression="SET tokens = :b",
                           ExpressionAttributeValues={":b": max(int(out["token_per_team_monthly"]), team_used)})
        try:
            invoke("Say OK.")   # this call is still allowed; its metered tokens trip the team's breaker
            tripped = wait(True, 30)   # invocation log -> meter -> EventBridge -> Step Functions -> IAM
            time.sleep(15)             # IAM propagation
            code, body = invoke("Say OK again.")
            model_denied = isinstance(body, dict) and body.get("trace", {}).get("model_denied") is True
            case("over-budget team: model calls denied (ADR 0003 breaker)", tripped and code == 200 and model_denied,
                 {"policy": "attached" if tripped else "not attached", "status": code, "model_denied": model_denied,
                  "type": (body.get("error") if isinstance(body, dict) else str(body)[:200])})
        finally:
            ledger.update_item(Key=tkey, UpdateExpression="SET tokens = :u", ExpressionAttributeValues={":u": team_used})
            for _ in range(2):   # heartbeat sweep: mark released + detach, then detach + forget
                lam.invoke(FunctionName=out["token_meter_function"], Payload=b"{}")
                time.sleep(20)
            released = wait(False, 18)
            case("team back under budget: breaker detached the deny policy", released,
                 {"policy": "detached" if released else "still attached"})
code, body = invoke("hello", bearer=None)
case("unauthenticated invocation rejected", code in (401, 403), {"status": code})
print("\n%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
