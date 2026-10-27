// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// SGEA tenant snippets (TypeScript, Node 20+): caller identity, guarded Converse,
// enclave gateway (MCP JSON-RPC), enclave memory, allow-listed logging.
// Environment: SGEA_MODEL_ID, SGEA_GUARDRAIL_ID, SGEA_GUARDRAIL_VERSION, SGEA_MEMORY_ID,
// SGEA_GATEWAY_URL, AWS_REGION (default "us-east-1").
import { randomUUID } from "node:crypto";
import {
  BedrockRuntimeClient,
  ConverseCommand,
  type ContentBlock,
  type ConverseCommandInput,
} from "@aws-sdk/client-bedrock-runtime";
import { BedrockAgentCoreClient, CreateEventCommand } from "@aws-sdk/client-bedrock-agentcore";
import { SignatureV4 } from "@smithy/signature-v4";
import { HttpRequest } from "@smithy/protocol-http";
import { Sha256 } from "@aws-crypto/sha256-js";
import { defaultProvider } from "@aws-sdk/credential-provider-node";

const REGION = process.env.AWS_REGION ?? "us-east-1";
const runtime = new BedrockRuntimeClient({ region: REGION });
const memory = new BedrockAgentCoreClient({ region: REGION });

// sgea:snippet:start caller
export function callerFromJwt(
  authorizationHeader: string | undefined,
  teamClaim = "cognito:groups",
): [string | null, string | null] {
  // The signature is NOT verified here: the AgentCore Runtime JWT authorizer has already validated
  // the token (the header reaches the container because request_header_allowlist includes "Authorization").
  try {
    const token = (authorizationHeader ?? "").trim().split(/\s+/).pop() ?? "";
    const segment = token.split(".")[1];
    if (!segment) return [null, null];
    const claims = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
    const user = typeof claims.sub === "string" ? claims.sub : null;
    const raw = claims[teamClaim];
    let team: string | null = null;
    if (Array.isArray(raw)) team = raw.length > 0 ? String(raw[0]) : null;
    else if (typeof raw === "string") team = raw;
    return [user, team];
  } catch {
    return [null, null];
  }
}
// sgea:snippet:end

// sgea:snippet:start converse
const SYSTEM_PROMPT = "You are a tenant agent running inside a governed enclave. Be brief.";

export async function converse(
  prompt: string,
  user: string | null,
  team: string | null,
): Promise<{ answer: string; blocked: boolean; stopReason: string | undefined }> {
  const input: ConverseCommandInput = {
    modelId: process.env.SGEA_MODEL_ID,
    guardrailConfig: {
      guardrailIdentifier: process.env.SGEA_GUARDRAIL_ID,
      guardrailVersion: process.env.SGEA_GUARDRAIL_VERSION,
      trace: "enabled",
    },
    // guardContent scopes guardrail evaluation to the user's input.
    messages: [{ role: "user", content: [{ guardContent: { text: { text: prompt } } }] }],
    // The system prompt is plain text and is not evaluated as guarded user input.
    system: [{ text: SYSTEM_PROMPT }],
  };
  const meta: Record<string, string> = {};
  if (user) meta.sgea_user = user;
  if (team) meta.sgea_team = team;
  // Lands in the model-invocation log; the enclave token meter credits per-user/per-team budgets from it.
  if (Object.keys(meta).length > 0) input.requestMetadata = meta;
  const out = await runtime.send(new ConverseCommand(input));
  const content: ContentBlock[] = out.output?.message?.content ?? [];
  // On guardrail_intervened the returned text is the enclave's blocked message.
  const answer = content.map((c) => c.text ?? "").join("");
  return { answer, blocked: out.stopReason === "guardrail_intervened", stopReason: out.stopReason };
}
// sgea:snippet:end

// sgea:snippet:start gateway
export async function gatewayCall(
  method: string,
  params: Record<string, unknown>,
  user: string | null,
  team: string | null,
  bearerToken: string | null = null,
): Promise<{ result?: unknown; error?: unknown; denied: boolean }> {
  const url = new URL(process.env.SGEA_GATEWAY_URL ?? "");
  if (url.protocol !== "https:") throw new Error("SGEA_GATEWAY_URL must be https");
  const body = JSON.stringify({ jsonrpc: "2.0", id: randomUUID(), method, params });
  const headers: Record<string, string> = {
    "Content-Type": "application/json", Accept: "application/json", host: url.host,
  };
  // Identifies the caller to the enclave token-budget interceptor; with token control on,
  // a tool call without an identifiable user is denied.
  if (user) headers["X-Sgea-User"] = user;
  if (team) headers["X-Sgea-Team"] = team;
  let sent = headers;
  if (bearerToken) {
    sent = { ...headers, Authorization: `Bearer ${bearerToken}` }; // CUSTOM_JWT gateway
  } else {
    const signer = new SignatureV4({
      service: "bedrock-agentcore", region: REGION, credentials: defaultProvider(), sha256: Sha256,
    });
    const request = new HttpRequest({
      method: "POST", protocol: url.protocol, hostname: url.hostname, path: url.pathname,
      query: Object.fromEntries(url.searchParams), headers, body,
    });
    sent = (await signer.sign(request)).headers; // AWS_IAM gateway
  }
  const res = await fetch(url, { method: "POST", headers: sent, body, signal: AbortSignal.timeout(30_000) });
  const doc = (await res.json()) as { result?: unknown; error?: unknown };
  // The gateway default-denies tools that no policy permits: that surfaces as a JSON-RPC error.
  return { ...doc, denied: "error" in doc };
}
// e.g. gatewayCall("tools/list", {}, user, team)
//      gatewayCall("tools/call", { name: "<target>___<tool>", arguments: {} }, user, team)
// sgea:snippet:end

// sgea:snippet:start memory
export async function recordTurn(
  sessionId: string,
  actorId: string,
  userText: string,
  answer: string,
): Promise<string | null> {
  const memoryId = process.env.SGEA_MEMORY_ID;
  if (!memoryId) return null;
  // Memory is enclave-shared and untagged: tenant separation rests on your actorId / sessionId
  // and IAM scoping.
  const out = await memory.send(new CreateEventCommand({
    memoryId,
    actorId,
    sessionId,
    eventTimestamp: new Date(),
    payload: [
      { conversational: { role: "USER", content: { text: userText } } },
      { conversational: { role: "ASSISTANT", content: { text: answer || "(no answer)" } } },
    ],
  }));
  return out.event?.eventId ?? null;
}
// sgea:snippet:end

// sgea:snippet:start log
const LOG_KEYS = new Set([
  "event", "status", "stop_reason", "blocked", "denied", "tool", "answer_chars", "session_id",
]);

export function logOutcome(event: string, fields: Record<string, unknown> = {}): void {
  // Never log prompts, answers, tool arguments or tokens (data-protection requirement):
  // any key outside the allow-list is dropped.
  const line: Record<string, unknown> = { event };
  for (const [key, value] of Object.entries(fields)) {
    if (LOG_KEYS.has(key) && key !== "event") line[key] = value;
  }
  process.stdout.write(JSON.stringify(line) + "\n");
}
// sgea:snippet:end
