# SGEA token meter: credits the token-control ledger from Bedrock model-invocation logs.
# Invoked by (a) the CloudWatch Logs subscription on the enclave invocation log group and
# (b) a schedule that writes the meter heartbeat (the gateway interceptor fails closed when
# the heartbeat is older than FAIL_CLOSED_HOURS).
# Attribution: Converse/InvokeModel requestMetadata sgea_user / sgea_team (set by the tenant
# runtime from the caller's validated JWT); otherwise the calling IAM principal.
# Ledger items: pk=user#<id> sk=day#YYYY-MM-DD, pk=team#<id> sk=month#YYYY-MM, attr tokens (N).
import base64, datetime, gzip, json, os, time

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["TOKEN_LEDGER_TABLE"])
TZ_NAME = os.environ.get("TOKEN_TIMEZONE", "UTC")


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
    TABLE.update_item(Key={"pk": pk, "sk": sk},
                      UpdateExpression="ADD tokens :t SET expires_at = :e",
                      ExpressionAttributeValues={":t": tokens, ":e": int(time.time()) + ttl_days * 86400})


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
        _add("team#" + team, month, tokens, 40)
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
    heartbeat()
    return {"ok": True}
