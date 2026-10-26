# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA AgentCore Gateway REQUEST interceptor. Two enclave controls, each enabled by env:
#  * tool-path policy (TOOL_POLICY_ENFORCE=true; stands in for the AgentCore policy engine where
#    AWS does not offer it, e.g. GovCloud). Only tools/call is evaluated; deny overrides allow;
#    no matching allow => DENY. Rules (env TOOL_POLICY, JSON list): {"effect":"allow|deny",
#    "tools":["glob"], "claim":"cognito:groups", "values":["glob"]} (claim/values optional = any caller)
#  * token budgets (TOKEN_LEDGER_TABLE set): deny tools/call once the caller's per-user daily or
#    per-team monthly tokens (credited by the SGEA token meter) reach the budget. Fails closed when
#    the caller cannot be identified, the ledger is unreadable, or the meter heartbeat is older
#    than FAIL_CLOSED_HOURS.
# Caller identity: claims of the bearer token the Gateway has ALREADY validated (CUSTOM_JWT);
# under AWS_IAM auth, the x-sgea-user / x-sgea-team headers set by the (IAM-authenticated)
# enclave workload from its own validated caller JWT.
import base64, datetime, fnmatch, json, os, time

RULES = json.loads(os.environ.get("TOOL_POLICY", "[]"))
TOOL_POLICY_ENFORCE = os.environ.get("TOOL_POLICY_ENFORCE", "true") == "true"
LEDGER = os.environ.get("TOKEN_LEDGER_TABLE")
USER_DAILY = int(os.environ.get("PER_USER_DAILY_TOKENS", "0"))
TEAM_MONTHLY = int(os.environ.get("PER_TEAM_MONTHLY_TOKENS", "0"))
FAIL_CLOSED_S = float(os.environ.get("FAIL_CLOSED_HOURS", "4")) * 3600
TEAM_CLAIM = os.environ.get("TEAM_CLAIM", "cognito:groups")
TZ_NAME = os.environ.get("TOKEN_TIMEZONE", "UTC")
_table = None


def _ledger():
    global _table
    if _table is None:
        import boto3
        _table = boto3.resource("dynamodb").Table(LEDGER)
    return _table


def _claims(headers):
    auth = headers.get("authorization", "")
    try:
        seg = auth.split()[-1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return {}


def _match(rule, tool, claims):
    if not any(fnmatch.fnmatchcase(tool, t) for t in rule.get("tools", [])):
        return False
    if "claim" not in rule:
        return True
    have = claims.get(rule["claim"], [])
    have = have if isinstance(have, list) else str(have).split()
    return any(fnmatch.fnmatchcase(str(h), v) for h in have for v in rule.get("values", []))


def decide(tool, claims):
    hits = [r for r in RULES if _match(r, tool, claims)]
    if any(r.get("effect") == "deny" for r in hits):
        return "DENY", "explicit deny"
    if any(r.get("effect") == "allow" for r in hits):
        return "ALLOW", "allow rule"
    return "DENY", "no allow rule (default deny)"


def caller(claims, headers):
    user = claims.get("sub") or headers.get("x-sgea-user")
    team = claims.get(TEAM_CLAIM) or headers.get("x-sgea-team")
    if isinstance(team, list):
        team = team[0] if team else None
    return user, team


def _periods():
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(TZ_NAME)
    except Exception:
        tz = datetime.timezone.utc
    now = datetime.datetime.now(tz)
    return "day#" + now.strftime("%Y-%m-%d"), "month#" + now.strftime("%Y-%m")


def _tokens(pk, sk):
    item = _ledger().get_item(Key={"pk": pk, "sk": sk}, ConsistentRead=True).get("Item") or {}
    return int(item.get("tokens", 0))


def budget(user, team):
    """(decision, reason) for the token budgets; DENY on any doubt (fail closed)."""
    if not user:
        return "DENY", "caller identity unknown (token budget fails closed)"
    try:
        beat = _ledger().get_item(Key={"pk": "meter", "sk": "heartbeat"}, ConsistentRead=True).get("Item") or {}
        if time.time() - float(beat.get("at", 0)) > FAIL_CLOSED_S:
            return "DENY", "token meter heartbeat stale (fail closed)"
        day, month = _periods()
        if USER_DAILY and _tokens("user#" + user, day) >= USER_DAILY:
            return "DENY", "per-user daily token budget exhausted"
        if team and TEAM_MONTHLY and _tokens("team#" + team, month) >= TEAM_MONTHLY:
            return "DENY", "per-team monthly token budget exhausted"
    except Exception as e:
        return "DENY", "token ledger unavailable (fail closed): " + type(e).__name__
    return "ALLOW", "within token budget"


def handler(event, context):
    mcp = event.get("mcp", {})
    req = mcp.get("gatewayRequest", {})
    body = req.get("body") or {}
    out = {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}
    if body.get("method") != "tools/call":
        return out
    tool = str((body.get("params") or {}).get("name", ""))
    headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    claims = _claims(headers)
    user, team = caller(claims, headers)
    decision, reason, control = "ALLOW", "no enclave control denied", None
    if TOOL_POLICY_ENFORCE:
        decision, reason = decide(tool, claims)
        control = "tool-policy"
    if decision == "ALLOW" and LEDGER:
        decision, reason = budget(user, team)
        control = "token-budget"
    print(json.dumps({"sgea": control or "interceptor", "decision": decision, "reason": reason, "tool": tool,
                      "user": user, "team": team, "client_id": claims.get("client_id")}))
    if decision == "DENY":
        out["mcp"]["transformedGatewayResponse"] = {"statusCode": 200, "body": {
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32003, "message": "Tool call denied by enclave %s: %s" % (control, reason)}}}
    return out
