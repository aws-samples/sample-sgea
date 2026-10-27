# SGEA sample agent — a tenant app on the enclave

Shows the enclave's service constructs working together, deployed the way a real tenant would:

```
user ──JWT (test Cognito IdP)──▶ AgentCore Runtime (VPC-only, SGEA agentcore-runtime wrapper)
                                    │  app/agent.py
                                    ├─ Bedrock Converse  ── enclave guardrail on every call (PII/PHI, filters)
                                    ├─ AgentCore Gateway ── MCP tools/list + tools/call (SigV4) ─▶ tool Lambda
                                    │                       (tool-path policy: policy engine, or the SGEA
                                    │                        interceptor Lambda in GovCloud)
                                    └─ AgentCore Memory  ── create_event (enclave CMK)
  all via the enclave VPC endpoints; logs KMS-encrypted at the baseline retention
```

| Path | |
|---|---|
| `app/` | Agent container (stdlib HTTP + boto3; `/ping`, `/invocations`), arm64 Dockerfile |
| `tool/` | `enclave_facts` Lambda, registered as an AgentCore Gateway Lambda target |
| `infra/` | Tenant Terraform: test IdP, tool (terraform-aws-modules/lambda), gateway target, least-privilege execution role, runtime via `./.sgea-modules/agentcore-runtime` (symlink to the enclave build), encrypted runtime log group |
| `scripts/build_push.sh` | finch build (linux/arm64) + push to the enclave ECR, content-derived immutable tag |
| `scripts/e2e_test.py` | 9 checks: authenticated call answers · gateway tool called (allowed by the tool policy) · PII prompt blocked by the guardrail · contextual PII masked, not blocked · token meter credits the caller · over-budget caller's tool calls denied · over-budget team's model calls denied by the token breaker (ADR 0003; the runtime role is tagged `sgea:team`) · breaker released once back under budget · unauthenticated call rejected |

`infra/` refuses (`check` block) a `model_id` whose foundation model is not on the enclave's authorized list.
Default: `us.anthropic.claude-haiku-4-5-20251001-v1:0` (FedRAMP Moderate–authorized). In a fresh account,
Anthropic models may need a one-time model-access use-case submission in the Bedrock console.

Run everything through `../run_sandbox_test.sh`; see `../README.md`.
