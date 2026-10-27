# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SGEA tenant snippets (Python): caller identity, guarded Converse, gateway tools, memory, logging.

Environment (set by the enclave runtime wrapper): SGEA_MODEL_ID, SGEA_GUARDRAIL_ID,
SGEA_GUARDRAIL_VERSION, SGEA_MEMORY_ID, SGEA_GATEWAY_URL, AWS_REGION (default us-east-1).
"""
import base64
import datetime
import json
import os
import urllib.request
import uuid

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REGION = os.environ.get("AWS_REGION", "us-east-1")
session = boto3.Session(region_name=REGION)
runtime = session.client("bedrock-runtime")
memory = session.client("bedrock-agentcore")


# sgea:snippet:start caller
def caller_from_jwt(authorization_header, team_claim="cognito:groups"):
    """(user, team) from the caller's JWT, or (None, None) on any decode error.

    The signature is NOT verified here: the AgentCore Runtime JWT authorizer has already
    validated the token. The header reaches the container because the runtime's
    request_header_allowlist includes "Authorization".
    """
    try:
        segment = authorization_header.split()[-1].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        user = claims.get("sub")
        value = claims.get(team_claim)
    except Exception:
        return None, None
    if isinstance(value, list):
        team = value[0] if value else None
    elif isinstance(value, str):
        team = value
    else:
        team = None
    return user, team
# sgea:snippet:end


# sgea:snippet:start converse
SYSTEM = [{"text": "You are a tenant agent running inside a governed enclave. Be brief."}]


def converse(prompt, user, team):
    """One guarded Converse turn -> {answer, blocked, stopReason}. Never logs prompt or answer."""
    kwargs = {
        "modelId": os.environ["SGEA_MODEL_ID"],
        # guardContent scopes guardrail evaluation to the user's input.
        "messages": [{"role": "user", "content": [{"guardContent": {"text": {"text": prompt}}}]}],
        "system": SYSTEM,  # plain text, not guarded
        "guardrailConfig": {"guardrailIdentifier": os.environ["SGEA_GUARDRAIL_ID"],
                            "guardrailVersion": os.environ["SGEA_GUARDRAIL_VERSION"],
                            "trace": "enabled"},
    }
    meta = {k: v for k, v in (("sgea_user", user), ("sgea_team", team)) if v}
    if meta:
        # Lands in the model-invocation log; the enclave token meter credits per-user/per-team budgets from it.
        kwargs["requestMetadata"] = meta
    out = runtime.converse(**kwargs)
    stop = out["stopReason"]
    # When blocked, the returned text is the enclave's blocked message.
    text = "".join(c.get("text", "") for c in out["output"]["message"]["content"])
    return {"answer": text, "blocked": stop == "guardrail_intervened", "stopReason": stop}
# sgea:snippet:end


# sgea:snippet:start gateway
def gateway_call(method, params, user, team, bearer_token=None):
    """MCP JSON-RPC 2.0 call to the enclave gateway -> parsed response plus "denied".

    Examples: gateway_call("tools/list", {}, u, t)
              gateway_call("tools/call", {"name": "<target>___<tool>", "arguments": {...}}, u, t)
    """
    url = os.environ.get("SGEA_GATEWAY_URL", "")
    if not url.startswith("https://"):  # B310: never file:/ or custom schemes
        raise ValueError("SGEA_GATEWAY_URL must be https")
    body = json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params})
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    # Identifies the caller to the enclave token-budget interceptor; with token control on,
    # a tool call without an identifiable user is denied.
    if user:
        headers["X-Sgea-User"] = user
    if team:
        headers["X-Sgea-Team"] = team
    if bearer_token:  # CUSTOM_JWT gateway authorizer
        headers["Authorization"] = f"Bearer {bearer_token}"
    else:  # AWS_IAM gateway authorizer: SigV4 with the default credential chain
        req = AWSRequest(method="POST", url=url, data=body, headers=headers)
        SigV4Auth(session.get_credentials().get_frozen_credentials(), "bedrock-agentcore", REGION).add_auth(req)
        headers = dict(req.headers.items())
    request = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
    with urllib.request.urlopen(request, timeout=30) as resp:  # nosec B310 - https enforced above
        doc = json.loads(resp.read())
    # The gateway default-denies tools that no policy permits; that surfaces as a JSON-RPC error.
    doc["denied"] = "error" in doc
    return doc
# sgea:snippet:end


# sgea:snippet:start memory
def record_turn(session_id, actor_id, user_text, answer):
    """Record one USER/ASSISTANT turn in AgentCore Memory -> eventId (None if SGEA_MEMORY_ID unset).

    Memory is enclave-shared and untagged: tenant separation rests on your actorId / sessionId
    and IAM scoping.
    """
    memory_id = os.environ.get("SGEA_MEMORY_ID")
    if not memory_id:
        return None
    event = memory.create_event(
        memoryId=memory_id, actorId=actor_id, sessionId=session_id,
        eventTimestamp=datetime.datetime.now(datetime.timezone.utc),
        payload=[{"conversational": {"content": {"text": user_text}, "role": "USER"}},
                 {"conversational": {"content": {"text": answer or "(no answer)"}, "role": "ASSISTANT"}}])
    return event["event"]["eventId"]
# sgea:snippet:end


# sgea:snippet:start log
LOG_KEYS = ("event", "status", "stop_reason", "blocked", "denied", "tool", "answer_chars", "session_id")


def log_outcome(event, fields=None):
    """One JSON line to stdout with allow-listed keys only.

    Never log prompts, answers, tool arguments or tokens (data-protection requirement);
    any other key is dropped.
    """
    record = {k: v for k, v in (fields or {}).items() if k in LOG_KEYS and k != "event"}
    print(json.dumps({"event": event, **record}), flush=True)
# sgea:snippet:end
