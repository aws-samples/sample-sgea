// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Amazon;
using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Amazon.BedrockRuntime;
using Amazon.BedrockRuntime.Model;
using Amazon.Runtime.Credentials;
using Amazon.Runtime.Signing;
using ContentBlock = Amazon.BedrockRuntime.Model.ContentBlock; // BedrockAgentCore.Model also defines ContentBlock

namespace Sgea.Tenant;

/// <summary>SGEA tenant snippets: caller identity, guarded Converse, gateway MCP call, memory, safe logging.</summary>
public static class SgeaTenant
{
    // sgea:snippet:start caller
    /// <summary>(user, team) from the caller's JWT. Signature is NOT verified here: the AgentCore Runtime
    /// JWT authorizer has already validated it (the header reaches the container because the runtime's
    /// request_header_allowlist includes "Authorization").</summary>
    public static (string? User, string? Team) CallerFromJwt(string? authorizationHeader, string teamClaim = "cognito:groups")
    {
        try
        {
            var seg = authorizationHeader!.Split(' ', StringSplitOptions.RemoveEmptyEntries)[^1].Split('.')[1];
            var b64 = seg.Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Convert.FromBase64String(b64));
            var root = doc.RootElement;
            string? user = root.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String ? sub.GetString() : null;
            string? team = null;
            if (root.TryGetProperty(teamClaim, out var t))
            {
                if (t.ValueKind == JsonValueKind.Array && t.GetArrayLength() > 0 && t[0].ValueKind == JsonValueKind.String)
                    team = t[0].GetString();
                else if (t.ValueKind == JsonValueKind.String)
                    team = t.GetString();
            }
            return (user, team);
        }
        catch (Exception)
        {
            return (null, null);
        }
    }
    // sgea:snippet:end

    // sgea:snippet:start converse
    public sealed record ConverseResult(string Answer, bool Blocked, string? StopReason);

    private static readonly AmazonBedrockRuntimeClient Runtime =
        new(RegionEndpoint.GetBySystemName(Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1"));

    /// <summary>Bedrock Converse with the enclave guardrail attached. Never log the prompt or the answer.</summary>
    public static async Task<ConverseResult> ConverseAsync(string prompt, string? user, string? team)
    {
        var request = new ConverseRequest
        {
            ModelId = Environment.GetEnvironmentVariable("SGEA_MODEL_ID"),
            GuardrailConfig = new GuardrailConfiguration
            {
                GuardrailIdentifier = Environment.GetEnvironmentVariable("SGEA_GUARDRAIL_ID"),
                GuardrailVersion = Environment.GetEnvironmentVariable("SGEA_GUARDRAIL_VERSION"),
                Trace = GuardrailTrace.Enabled,
            },
            // System prompt is plain text and not guarded.
            System = new List<SystemContentBlock> { new() { Text = "You are a tenant agent inside a governed enclave. Be brief." } },
            // guardContent scopes guardrail evaluation to the user's input.
            Messages = new List<Message> { new() { Role = ConversationRole.User, Content = new List<ContentBlock> {
                new() { GuardContent = new GuardrailConverseContentBlock { Text = new GuardrailConverseTextBlock { Text = prompt } } } } } },
        };
        var meta = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(user)) meta["sgea_user"] = user;
        if (!string.IsNullOrEmpty(team)) meta["sgea_team"] = team;
        // Lands in the model-invocation log; the enclave token meter credits the per-user/per-team budget from it.
        if (meta.Count > 0) request.RequestMetadata = meta;

        var response = await Runtime.ConverseAsync(request).ConfigureAwait(false);
        var answer = string.Concat((response.Output?.Message?.Content ?? new List<ContentBlock>()).Select(c => c.Text ?? ""));
        var blocked = response.StopReason == StopReason.Guardrail_intervened; // answer is then the enclave's blocked message
        return new ConverseResult(answer, blocked, response.StopReason?.Value);
    }
    // sgea:snippet:end

    // sgea:snippet:start gateway
    public sealed record GatewayResult(JsonNode? Result, JsonNode? Error, bool Denied);

    private static readonly Lazy<HttpClient> SignedHttp = new(() => new HttpClient(new SigV4SigningHandler(
        DefaultAWSCredentialsIdentityResolver.GetCredentials(),
        RegionEndpoint.GetBySystemName(Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1"),
        "bedrock-agentcore", new HttpClientHandler())) { Timeout = TimeSpan.FromSeconds(30) });
    private static readonly HttpClient PlainHttp = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>MCP JSON-RPC call to the enclave AgentCore Gateway, e.g. ("tools/list", {}) or
    /// ("tools/call", {"name": "target___tool", "arguments": {...}}).</summary>
    public static async Task<GatewayResult> GatewayCallAsync(string method, JsonObject parameters, string? user, string? team, string? bearerToken = null)
    {
        var url = Environment.GetEnvironmentVariable("SGEA_GATEWAY_URL") ?? "";
        if (!url.StartsWith("https://", StringComparison.Ordinal)) throw new InvalidOperationException("SGEA_GATEWAY_URL must be https");
        var body = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = Guid.NewGuid().ToString(), ["method"] = method, ["params"] = parameters.DeepClone() };
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        // Identifies the caller to the enclave token-budget interceptor; with token control on, a tool call without an identifiable user is denied.
        if (!string.IsNullOrEmpty(user)) req.Headers.Add("X-Sgea-User", user);
        if (!string.IsNullOrEmpty(team)) req.Headers.Add("X-Sgea-Team", team);
        // CUSTOM_JWT gateway: bearer token; AWS_IAM gateway: SigV4 (default credential chain).
        if (bearerToken is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        var http = bearerToken is not null ? PlainHttp : SignedHttp.Value;

        using var resp = await http.SendAsync(req).ConfigureAwait(false);
        var doc = JsonNode.Parse(await resp.Content.ReadAsStringAsync().ConfigureAwait(false)) as JsonObject ?? new JsonObject();
        // The gateway default-denies tools that no policy permits: that surfaces as a JSON-RPC "error".
        var error = doc["error"];
        return new GatewayResult(doc["result"]?.DeepClone(), error?.DeepClone(), error is not null);
    }
    // sgea:snippet:end

    // sgea:snippet:start memory
    private static readonly AmazonBedrockAgentCoreClient Memory =
        new(RegionEndpoint.GetBySystemName(Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1"));

    /// <summary>Record one turn in the enclave AgentCore Memory. Memory is enclave-shared and untagged:
    /// tenant separation rests on your actorId / sessionId and IAM scoping. Returns null if SGEA_MEMORY_ID is unset.</summary>
    public static async Task<string?> RecordTurnAsync(string sessionId, string actorId, string userText, string? answer)
    {
        var memoryId = Environment.GetEnvironmentVariable("SGEA_MEMORY_ID");
        if (string.IsNullOrEmpty(memoryId)) return null;
        var response = await Memory.CreateEventAsync(new CreateEventRequest
        {
            MemoryId = memoryId,
            ActorId = actorId,
            SessionId = sessionId,
            EventTimestamp = DateTime.UtcNow,
            Payload = new List<PayloadType>
            {
                new() { Conversational = new Conversational { Role = Role.USER, Content = new Content { Text = userText } } },
                new() { Conversational = new Conversational { Role = Role.ASSISTANT, Content = new Content { Text = string.IsNullOrEmpty(answer) ? "(no answer)" : answer } } },
            },
        }).ConfigureAwait(false);
        return response.Event?.EventId;
    }
    // sgea:snippet:end

    // sgea:snippet:start log
    private static readonly HashSet<string> LogKeys = new(StringComparer.Ordinal)
        { "event", "status", "stop_reason", "blocked", "denied", "tool", "answer_chars", "session_id" };

    /// <summary>One JSON line to stdout with allow-listed keys only. Never log prompts, answers, tool
    /// arguments or tokens (data-protection requirement); any other key is dropped.</summary>
    public static void LogOutcome(string eventName, IReadOnlyDictionary<string, object?> fields)
    {
        var line = new Dictionary<string, object?> { ["event"] = eventName };
        foreach (var (key, value) in fields)
            if (LogKeys.Contains(key) && key != "event") line[key] = value;
        Console.WriteLine(JsonSerializer.Serialize(line));
    }
    // sgea:snippet:end
}
