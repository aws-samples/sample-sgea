"""
SGEA sample agent — an AgentCore Runtime container deployed as a tenant of the enclave.

Contract (AgentCore Runtime, HTTP protocol): GET /ping, POST /invocations on port 8080.
Per request it exercises the enclave's service constructs:
  * Bedrock Converse with the enclave guardrail attached (SGEA_GUARDRAIL_ID / _VERSION)
  * tools discovered from and executed through the enclave AgentCore Gateway (MCP, SigV4),
    so the gateway tool-path policy applies
  * the turn recorded in the enclave AgentCore Memory (SGEA_MEMORY_ID)
All traffic leaves through the enclave VPC endpoints — the runtime has no internet path.
"""
import base64, datetime, json, os, uuid, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ["SGEA_MODEL_ID"]
GUARDRAIL = {"guardrailIdentifier": os.environ["SGEA_GUARDRAIL_ID"],
             "guardrailVersion": os.environ["SGEA_GUARDRAIL_VERSION"], "trace": "enabled"}
MEMORY_ID = os.environ.get("SGEA_MEMORY_ID")
GATEWAY_URL = os.environ.get("SGEA_GATEWAY_URL")
SYSTEM = [{"text": "You are the SGEA sample agent running inside a governed enclave. "
                   "Use the available tools to answer questions about the enclave. Be brief."}]

session = boto3.Session(region_name=REGION)
runtime = session.client("bedrock-runtime")
memory = session.client("bedrock-agentcore")


def caller(authorization):
    """(user, team) from the caller's JWT. The runtime's JWT authorizer has already validated it;
    the enclave token budgets are keyed on these (gateway headers + Converse requestMetadata)."""
    try:
        seg = authorization.split()[-1].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return None, None
    groups = claims.get("cognito:groups") or []
    return claims.get("sub"), (groups[0] if groups else None)


def mcp(method, params=None, who=(None, None)):
    """JSON-RPC call to the enclave AgentCore Gateway, SigV4-signed (gateway authorizer AWS_IAM)."""
    body = json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params or {}})
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if who[0]:
        headers["X-Sgea-User"] = who[0]
    if who[1]:
        headers["X-Sgea-Team"] = who[1]
    req = AWSRequest(method="POST", url=GATEWAY_URL, data=body, headers=headers)
    SigV4Auth(session.get_credentials().get_frozen_credentials(), "bedrock-agentcore", REGION).add_auth(req)
    if not GATEWAY_URL.startswith("https://"):  # B310: never file:/ or custom schemes
        raise ValueError("SGEA_GATEWAY_URL must be https")
    with urllib.request.urlopen(urllib.request.Request(GATEWAY_URL, data=body.encode(), method="POST",  # nosec B310 - https enforced above
                                                       headers=dict(req.headers.items())), timeout=30) as r:
        return json.loads(r.read())


def tool_config(who):
    if not GATEWAY_URL:
        return None, []
    tools = mcp("tools/list", who=who).get("result", {}).get("tools", [])
    specs = [{"toolSpec": {"name": t["name"], "description": t.get("description", t["name"]),
                           "inputSchema": {"json": t.get("inputSchema", {"type": "object"})}}} for t in tools]
    return ({"tools": specs} if specs else None), [t["name"] for t in tools]


def run(prompt, session_id, who=(None, None)):
    trace = {"model": MODEL_ID, "guardrail": GUARDRAIL["guardrailIdentifier"], "tools": [], "tool_calls": []}
    tools, trace["tools"] = tool_config(who)
    meta = {k: v for k, v in (("sgea_user", who[0]), ("sgea_team", who[1])) if v}
    # guardContent scopes guardrail evaluation to the user's input: the system prompt and tool results
    # are not scanned as user input (AWS: required for the prompt-attack filter to work as intended).
    messages = [{"role": "user", "content": [{"guardContent": {"text": {"text": prompt}}}]}]
    answer = ""
    for _ in range(4):
        kwargs = {"modelId": MODEL_ID, "messages": messages, "system": SYSTEM, "guardrailConfig": GUARDRAIL}
        if meta:
            kwargs["requestMetadata"] = meta  # lands in the invocation log -> enclave token meter
        if tools:
            kwargs["toolConfig"] = tools
        out = runtime.converse(**kwargs)
        trace["stop_reason"] = out["stopReason"]
        msg = out["output"]["message"]
        messages.append(msg)
        if out["stopReason"] == "guardrail_intervened":
            answer = "".join(c.get("text", "") for c in msg["content"])
            trace["guardrail_action"] = "INTERVENED"
            gr = (out.get("trace") or {}).get("guardrail", {})
            trace["guardrail_policies"] = sorted({k for a in gr.get("inputAssessment", {}).values() for k in a}
                                                 | {k for v in gr.get("outputAssessments", {}).values() for a in v for k in a})
            trace["guardrail_findings"] = findings(gr)
            break
        uses = [c["toolUse"] for c in msg["content"] if "toolUse" in c]
        if not uses:
            answer = "".join(c.get("text", "") for c in msg["content"])
            break
        results = []
        for u in uses:
            res = mcp("tools/call", {"name": u["name"], "arguments": u.get("input", {})}, who=who)
            denied = "error" in res
            call = {"tool": u["name"], "denied_by_policy": denied}
            if denied:
                call["reason"] = str(res["error"].get("message", ""))[:200]
            trace["tool_calls"].append(call)
            text = json.dumps(res.get("error") if denied else res.get("result", {}))
            results.append({"toolResult": {"toolUseId": u["toolUseId"], "content": [{"text": text}],
                                           "status": "error" if denied else "success"}})
        messages.append({"role": "user", "content": results})
    if MEMORY_ID:
        ev = memory.create_event(memoryId=MEMORY_ID, actorId="sample-agent", sessionId=session_id,
                                 eventTimestamp=datetime.datetime.now(datetime.timezone.utc),
                                 payload=[{"conversational": {"content": {"text": prompt}, "role": "USER"}},
                                          {"conversational": {"content": {"text": answer or "(no answer)"}, "role": "ASSISTANT"}}])
        trace["memory_event_id"] = ev["event"]["eventId"]
    return {"answer": answer, "trace": trace}


def findings(gr):
    """Which guardrail filter fired, on which side (types/actions only — never the matched text)."""
    out = []
    sides = [("input", a) for a in gr.get("inputAssessment", {}).values()] + \
            [("output", a) for v in gr.get("outputAssessments", {}).values() for a in v]
    for side, a in sides:
        for f in (a.get("contentPolicy") or {}).get("filters", []):
            out.append({"side": side, "policy": "content", "type": f.get("type"),
                        "confidence": f.get("confidence"), "action": f.get("action")})
        for e in (a.get("sensitiveInformationPolicy") or {}).get("piiEntities", []):
            out.append({"side": side, "policy": "pii", "type": e.get("type"), "action": e.get("action")})
        for t in (a.get("topicPolicy") or {}).get("topics", []):
            out.append({"side": side, "policy": "topic", "type": t.get("name"), "action": t.get("action")})
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, doc):
        body = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"status": "Healthy"}) if self.path == "/ping" else self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/invocations":
            return self._send(404, {"error": "not found"})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            sid = self.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id") or str(uuid.uuid4()) * 2
            who = caller(self.headers.get("Authorization", ""))
            self._send(200, run(str(req.get("prompt", "")), sid[:100], who))
        except Exception as e:  # report, never leak credentials / tokens
            self._send(500, {"error": type(e).__name__, "message": str(e)[:500]})

    def log_message(self, fmt, *args):  # one line per request to stdout -> CloudWatch
        print(json.dumps({"path": self.path, "status": args[1] if len(args) > 1 else None}))


if __name__ == "__main__":
    # AgentCore Runtime contract: the container listens on 0.0.0.0:8080 (reachable only through the runtime).
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # nosec B104
