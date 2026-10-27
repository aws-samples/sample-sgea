// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
package com.example.sgea;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrockagentcore.BedrockAgentCoreClient;
import software.amazon.awssdk.services.bedrockagentcore.model.Conversational;
import software.amazon.awssdk.services.bedrockagentcore.model.CreateEventRequest;
import software.amazon.awssdk.services.bedrockagentcore.model.PayloadType;
import software.amazon.awssdk.services.bedrockagentcore.model.Role;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.bedrockruntime.model.ContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.ConversationRole;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseRequest;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseResponse;
import software.amazon.awssdk.services.bedrockruntime.model.GuardrailConverseContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.GuardrailConverseTextBlock;
import software.amazon.awssdk.services.bedrockruntime.model.Message;
import software.amazon.awssdk.services.bedrockruntime.model.StopReason;
import software.amazon.awssdk.services.bedrockruntime.model.SystemContentBlock;

/** SGEA tenant snippets: the five enclave integration units an AgentCore Runtime tenant needs. */
public final class SgeaTenant {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "us-east-1");

    private SgeaTenant() {
    }

    // sgea:snippet:start caller
    public record Caller(String user, String team) { }

    /**
     * (user, team) from the caller's JWT. The signature is NOT verified here: the AgentCore Runtime
     * JWT authorizer has already validated it (the header reaches the container because the
     * runtime's request_header_allowlist includes "Authorization").
     */
    public static Caller callerFromJwt(String authorizationHeader, String teamClaim) {
        try {
            String[] parts = authorizationHeader.trim().split("\\s+");
            String payload = parts[parts.length - 1].split("\\.")[1];
            JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(payload));
            JsonNode t = claims.path(teamClaim == null ? "cognito:groups" : teamClaim);
            String team = t.isArray() && t.size() > 0 ? t.get(0).asText() : t.isTextual() ? t.asText() : null;
            return new Caller(claims.hasNonNull("sub") ? claims.get("sub").asText() : null, team);
        } catch (RuntimeException | IOException e) {
            return new Caller(null, null);
        }
    }

    public static Caller callerFromJwt(String authorizationHeader) {
        return callerFromJwt(authorizationHeader, "cognito:groups");
    }
    // sgea:snippet:end

    // sgea:snippet:start converse
    public record ConverseResult(String answer, boolean blocked, String stopReason) { }

    private static final BedrockRuntimeClient RUNTIME = BedrockRuntimeClient.builder().region(Region.of(REGION)).build();

    /** One guarded Converse turn. Never log the prompt or the answer. */
    public static ConverseResult converse(String prompt, String user, String team) {
        // guardContent scopes guardrail evaluation to the user's input; the system prompt is not guarded.
        Message msg = Message.builder().role(ConversationRole.USER).content(ContentBlock.fromGuardContent(
                GuardrailConverseContentBlock.fromText(GuardrailConverseTextBlock.builder().text(prompt).build()))).build();
        ConverseRequest.Builder req = ConverseRequest.builder()
                .modelId(System.getenv("SGEA_MODEL_ID"))
                .system(SystemContentBlock.fromText("You are a tenant agent inside a governed enclave. Be brief."))
                .messages(msg)
                .guardrailConfig(g -> g.guardrailIdentifier(System.getenv("SGEA_GUARDRAIL_ID"))
                        .guardrailVersion(System.getenv("SGEA_GUARDRAIL_VERSION")).trace("enabled"));
        Map<String, String> meta = new LinkedHashMap<>();
        if (user != null && !user.isEmpty()) meta.put("sgea_user", user);
        if (team != null && !team.isEmpty()) meta.put("sgea_team", team);
        if (!meta.isEmpty()) {
            req.requestMetadata(meta); // lands in the invocation log; the enclave token meter credits user/team budgets
        }
        ConverseResponse out = RUNTIME.converse(req.build());
        String answer = out.output().message().content().stream()
                .map(ContentBlock::text).filter(s -> s != null).collect(Collectors.joining());
        // On guardrail_intervened the returned text is the enclave's blocked message.
        return new ConverseResult(answer, out.stopReason() == StopReason.GUARDRAIL_INTERVENED, out.stopReasonAsString());
    }
    // sgea:snippet:end

    // sgea:snippet:start gateway
    public record GatewayResult(JsonNode result, JsonNode error, boolean denied) { }

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();

    /** MCP JSON-RPC 2.0 call to the enclave AgentCore Gateway (bearer token or SigV4). */
    public static GatewayResult gatewayCall(String method, Object params, String user, String team, String bearerToken)
            throws IOException, InterruptedException {
        URI url = URI.create(System.getenv("SGEA_GATEWAY_URL"));
        if (!"https".equals(url.getScheme())) throw new IllegalArgumentException("SGEA_GATEWAY_URL must be https");
        String body = JSON.writeValueAsString(Map.of("jsonrpc", "2.0", "id", UUID.randomUUID().toString(),
                "method", method, "params", params == null ? Map.of() : params));
        Map<String, String> headers = new LinkedHashMap<>(Map.of("Content-Type", "application/json", "Accept", "application/json"));
        // Identifies the caller to the enclave token-budget interceptor; with token control on,
        // a tool call without an identifiable user is denied.
        if (user != null && !user.isEmpty()) headers.put("X-Sgea-User", user);
        if (team != null && !team.isEmpty()) headers.put("X-Sgea-Team", team);
        if (bearerToken != null) {
            headers.put("Authorization", "Bearer " + bearerToken); // CUSTOM_JWT gateway authorizer
        } else { // AWS_IAM gateway authorizer: SigV4 with the default credential chain
            SdkHttpRequest.Builder unsigned = SdkHttpRequest.builder().method(SdkHttpMethod.POST).uri(url);
            headers.forEach(unsigned::putHeader);
            AwsCredentials creds = DefaultCredentialsProvider.builder().build().resolveCredentials();
            SignedRequest signed = AwsV4HttpSigner.create().sign(r -> r.identity(creds).request(unsigned.build())
                    .payload(ContentStreamProvider.fromUtf8String(body))
                    .putProperty(AwsV4HttpSigner.SERVICE_SIGNING_NAME, "bedrock-agentcore")
                    .putProperty(AwsV4HttpSigner.REGION_NAME, REGION));
            signed.request().headers().forEach((k, v) -> headers.put(k, v.get(0)));
        }
        HttpRequest.Builder req = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        headers.forEach((k, v) -> { if (!Set.of("host", "content-length").contains(k.toLowerCase())) req.header(k, v); });
        JsonNode doc = JSON.readTree(HTTP.send(req.build(), HttpResponse.BodyHandlers.ofString()).body());
        // The gateway default-denies tools that no policy permits: that surfaces as a JSON-RPC error.
        return new GatewayResult(doc.get("result"), doc.get("error"), doc.has("error"));
    }

    // e.g. gatewayCall("tools/list", Map.of(), u, t)
    //      gatewayCall("tools/call", Map.of("name", "<target>___<tool>", "arguments", Map.of()), u, t)
    public static GatewayResult gatewayCall(String method, Object params, String user, String team)
            throws IOException, InterruptedException {
        return gatewayCall(method, params, user, team, null);
    }
    // sgea:snippet:end

    // sgea:snippet:start memory
    private static final BedrockAgentCoreClient MEMORY = BedrockAgentCoreClient.builder().region(Region.of(REGION)).build();

    /**
     * Records one turn in the enclave AgentCore Memory. Memory is enclave-shared and untagged:
     * tenant separation rests on your actorId / sessionId and IAM scoping.
     */
    public static String recordTurn(String sessionId, String actorId, String userText, String answer) {
        String memoryId = System.getenv("SGEA_MEMORY_ID");
        if (memoryId == null || memoryId.isEmpty()) return null;
        String reply = answer == null || answer.isEmpty() ? "(no answer)" : answer;
        CreateEventRequest req = CreateEventRequest.builder()
                .memoryId(memoryId).actorId(actorId).sessionId(sessionId)
                .eventTimestamp(Instant.now()) // Instant is UTC
                .payload(List.of(turn(Role.USER, userText), turn(Role.ASSISTANT, reply)))
                .build();
        return MEMORY.createEvent(req).event().eventId();
    }

    private static PayloadType turn(Role role, String text) {
        return PayloadType.fromConversational(Conversational.builder().role(role)
                .content(c -> c.text(text)).build());
    }
    // sgea:snippet:end

    // sgea:snippet:start log
    private static final Set<String> LOG_KEYS = Set.of(
            "status", "stop_reason", "blocked", "denied", "tool", "answer_chars", "session_id");

    /**
     * One JSON line to stdout with allow-listed keys only. Never log prompts, answers, tool
     * arguments or tokens (data-protection requirement); any other key is dropped.
     */
    public static void logOutcome(String event, Map<String, ?> fields) {
        ObjectNode line = JSON.createObjectNode().put("event", event);
        if (fields != null) {
            fields.forEach((k, v) -> { if (LOG_KEYS.contains(k)) line.set(k, JSON.valueToTree(v)); });
        }
        try {
            System.out.println(JSON.writeValueAsString(line));
        } catch (JsonProcessingException e) {
            System.out.println("{\"event\":\"log_error\"}");
        }
    }
    // sgea:snippet:end
}
