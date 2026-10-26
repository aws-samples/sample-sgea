"""
SGEA sample tool — a Lambda target behind the enclave AgentCore Gateway.
Tool `enclave_facts`: returns non-sensitive facts about the enclave the agent runs in.
Gateway Lambda contract: event = tool arguments; tool name in
context.client_context.custom['bedrockAgentCoreToolName'] ('<target>___<tool>').
"""
import datetime, json, os


def handler(event, context):
    tool = ""
    try:
        tool = context.client_context.custom.get("bedrockAgentCoreToolName", "")
    except Exception:
        pass
    facts = {
        "profile": os.environ.get("SGEA_PROFILE"),
        "region": os.environ.get("AWS_REGION"),
        # No opaque identifiers (guardrail id, ARNs): the model echoes them, and random ids can match the
        # guardrail's AWS_ACCESS_KEY detector, which BLOCKS the answer (observed in the Part 11 CDK sandbox run).
        "guardrail": "enclave baseline guardrail enforced on every model call",
        "controls": "logs are KMS-encrypted and retained per baseline; runtimes are VPC-only; tool calls pass the gateway policy",
        "topic": (event or {}).get("topic"),
        "tool": tool,
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    print(json.dumps({"sgea": "tool-call", "tool": tool, "topic": facts["topic"]}))
    return facts
