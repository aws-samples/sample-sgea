# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA token meter: credits the token-control ledger from Bedrock model-invocation logs.
# Invoked by (a) the CloudWatch Logs subscription on the enclave invocation log group and
# (b) a schedule that writes the meter heartbeat (the gateway interceptor fails closed when
# the heartbeat is older than FAIL_CLOSED_HOURS).
# Attribution: Converse/InvokeModel requestMetadata sgea_user / sgea_team (set by the tenant
# runtime from the caller's validated JWT); otherwise the calling IAM principal.
# Ledger items: pk=user#<id> sk=day#YYYY-MM-DD, pk=team#<id> sk=month#YYYY-MM, attr tokens (N).
# Model-call breaker (ADR 0003, TOKEN_BREAKER=1): once a team's month reaches PER_TEAM_MONTHLY_TOKENS,
# the calling runtime role is recorded (pk=breaker sk=role#<name>) and an EventBridge event asks the
# enclave state machine to attach the deny policy (only to roles tagged sgea:team = that team). Each
# heartbeat re-asserts active trips and releases them at month rollover, when the budget is raised,
# or when an operator writes pk=override sk=team#<id>#month#YYYY-MM. The meter never calls IAM: the
# enclave VPC has no IAM endpoint. The state machine acts only on what this ledger says (attach: an
# active trip for that role and team; detach: no trip or a released one), so a forged event does nothing.
import base64, datetime, gzip, json, os, time

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["TOKEN_LEDGER_TABLE"])
TZ_NAME = os.environ.get("TOKEN_TIMEZONE", "UTC")
TEAM_MONTHLY = int(os.environ.get("PER_TEAM_MONTHLY_TOKENS", "0"))
BREAKER = os.environ.get("TOKEN_BREAKER") == "1" and TEAM_MONTHLY > 0
SOURCE = os.environ.get("TOKEN_BREAKER_SOURCE", "sgea.token-meter")
DETAIL_TYPE = os.environ.get("TOKEN_BREAKER_DETAIL_TYPE", "SGEA Token Budget Breaker")
_events = None


def _tz():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(TZ_NAME)
    except Exception:
        return datetime.timezone.utc


def periods(now=None):
    now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(_tz())
    return "day#" + now.strftime("%Y-%m-%d"), "month#" + now.strftime("%Y-%m")


def _add(pk, sk, tokens, ttl_days):
    """Credit `tokens`; returns the new total."""
    r = TABLE.update_item(Key={"pk": pk, "sk": sk}, ReturnValues="UPDATED_NEW",
                          UpdateExpression="ADD tokens :t SET expires_at = :e",
                          ExpressionAttributeValues={":t": tokens, ":e": int(time.time()) + ttl_days * 86400})
    return int(r.get("Attributes", {}).get("tokens", tokens))


def role_name(arn):
    """arn:<p>:sts::<acct>:assumed-role/<role>/<session> -> <role>; anything else -> None."""
    parts = str(arn or "").split(":", 5)
    if len(parts) == 6 and parts[2] == "sts" and parts[5].startswith("assumed-role/"):
        return parts[5].split("/")[1] or None
    return None


def _overridden(team, month):
    return "Item" in TABLE.get_item(Key={"pk": "override", "sk": "team#%s#%s" % (team, month)}, ConsistentRead=True)


def _team_tokens(team, month):
    return int((TABLE.get_item(Key={"pk": "team#" + team, "sk": month}, ConsistentRead=True).get("Item") or {}).get("tokens", 0))


def _emit(items):
    """One event per batch of role actions -> the enclave breaker state machine."""
    global _events
    if not items:
        return
    _events = _events or boto3.client("events")
    for i in range(0, len(items), 50):
        r = _events.put_events(Entries=[{"Source": SOURCE, "DetailType": DETAIL_TYPE,
                                         "Detail": json.dumps({"roles": items[i:i + 50]})}])
        if r.get("FailedEntryCount"):
            raise RuntimeError("breaker event not accepted: " + str(r["Entries"][0].get("ErrorCode")))


def trip(team, role, month):
    """Record the trip (once per role and month) and ask for the deny policy to be attached."""
    if _overridden(team, month):
        return False
    try:
        TABLE.put_item(Item={"pk": "breaker", "sk": "role#" + role, "team": team, "month": month, "at": int(time.time())},
                       ConditionExpression="attribute_not_exists(pk) OR #m <> :m OR team <> :t OR released = :y",
                       ExpressionAttributeNames={"#m": "month"}, ExpressionAttributeValues={":m": month, ":t": team, ":y": True})
    except TABLE.meta.client.exceptions.ConditionalCheckFailedException:
        return False   # already tripped this month: the heartbeat re-asserts it
    _emit([{"role": role, "team": team, "action": "attach"}])
    return True


def sweep():
    """Heartbeat: re-attach active trips; release stale / lifted ones in two steps (mark released + detach,
    then detach again + delete on the next heartbeat), so the state machine always sees the release."""
    _, month = periods()
    items, kw = [], {"KeyConditionExpression": "pk = :p", "ExpressionAttributeValues": {":p": "breaker"}}
    while True:
        r = TABLE.query(**kw)
        items += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            break
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
    actions, done, active_n = [], [], 0
    for it in items:
        role, team = it["sk"][len("role#"):], it["team"]
        if it.get("released"):
            actions.append({"role": role, "team": team, "action": "detach"})
            done.append(it["sk"])
        elif it["month"] == month and _team_tokens(team, month) >= TEAM_MONTHLY and not _overridden(team, month):
            actions.append({"role": role, "team": team, "action": "attach"})
            active_n += 1
        else:
            TABLE.update_item(Key={"pk": "breaker", "sk": it["sk"]}, UpdateExpression="SET released = :y",
                              ExpressionAttributeValues={":y": True})
            actions.append({"role": role, "team": team, "action": "detach"})
    _emit(actions)
    for sk in done:   # second detach accepted: forget the trip (unless it re-tripped meanwhile)
        try:
            TABLE.delete_item(Key={"pk": "breaker", "sk": sk}, ConditionExpression="released = :y",
                              ExpressionAttributeValues={":y": True})
        except TABLE.meta.client.exceptions.ConditionalCheckFailedException:
            pass
    return active_n, len(actions) - active_n


def heartbeat():
    TABLE.put_item(Item={"pk": "meter", "sk": "heartbeat", "at": int(time.time())})


def record(entry):
    """One model-invocation log record -> ledger increments. Returns (user, team, tokens)."""
    tokens = int((entry.get("input") or {}).get("inputTokenCount") or 0) + \
        int((entry.get("output") or {}).get("outputTokenCount") or 0)
    if tokens <= 0:
        return None
    meta = entry.get("requestMetadata") or {}
    user = meta.get("sgea_user") or "principal:" + str((entry.get("identity") or {}).get("arn", "unknown"))
    team = meta.get("sgea_team")
    day, month = periods()
    _add("user#" + user, day, tokens, 3)
    if team:
        total = _add("team#" + team, month, tokens, 40)
        role = role_name((entry.get("identity") or {}).get("arn"))
        if BREAKER and role and total >= TEAM_MONTHLY:
            try:
                trip(team, role, month)
            except Exception as err:  # never fail (and re-deliver, double-crediting) a credited batch
                print(json.dumps({"sgea": "token-meter", "breaker": "deferred to heartbeat", "error": type(err).__name__}))
    return user, team, tokens


def handler(event, context):
    if "awslogs" in event:
        doc = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
        n = 0
        for e in doc.get("logEvents", []):
            try:
                if record(json.loads(e["message"])):
                    n += 1
            except (ValueError, KeyError) as err:  # never log the record: it holds prompts
                print(json.dumps({"sgea": "token-meter", "skipped": type(err).__name__}))
        print(json.dumps({"sgea": "token-meter", "records": n}))
    elif BREAKER:   # schedule: errors surface on the meter-errors alarm
        active, released = sweep()
        print(json.dumps({"sgea": "token-meter", "breaker_active": active, "breaker_released": released}))
    heartbeat()
    return {"ok": True}
