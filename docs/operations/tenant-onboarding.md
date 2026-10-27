# Tenant onboarding

What an application team does to deploy an agent into the enclave. The reference implementation is
`examples/sample-agent` (agent container in `app/`, gateway tool Lambda in `tool/`, tenant Terraform in `infra/`,
`scripts/build_push.sh`, `scripts/e2e_test.py`); every requirement below is either enforced by the enclave or checked
by the conformance packs on tenant resources. The enclave team owns everything named `sgea-<env>-*` that the enclave
export creates; the tenant owns its own stack.

Build and review against the requirements contract: [tenant requirements](tenant-requirements.md) (TR-01–TR-25, with code for Python, Node.js, .NET and Java). Related: [change and upgrade](change-and-upgrade.md), [access review](access-review.md),
[key and secret management](key-and-secret-management.md).

![Application-team responsibility matrix: inherited from the enclave (baseline guardrail, identity framework and gateway JWT authorizer, tenant-isolation SCPs / RCPs and data perimeter, model allow-list, enclave CMK, network endpoints, logging and conformance packs, token budgets, backup and detective controls, the control baseline and evidence) versus owned by the application team (agent code, its data, OIDC app client, scoped execution role, container image, tool Lambdas, gateway tool registration, runtime via the SGEA wrapper, tenant and profile tags, its full requirement scope and ATO).](../diagrams/sgea_04_app_responsibility.png)

*Tag keys are case-sensitive: use exactly `sgea:tenant` and `sgea:profile` (the tenant-isolation SCP compares `aws:PrincipalTag/sgea:tenant` with the resource tag).*

## 1. What the enclave gives a tenant

The enclave publishes its facts as one output: Terraform `terraform output -json enclave` (in
`build/<profile-id>/terraform`), CDK the `Enclave` output of stack `SgeaEnclave`. The sample's `infra/variables.tf`
(`variable "enclave"`) consumes it.

| Field | Use |
|---|---|
| `env`, `profile`, `partition`, `region` | Naming (`sgea-<env>-<tenant>-*`), tags, ARNs |
| `kms_key_arn` | Enclave CMK for tenant log groups, Lambda environment, DLQs |
| `guardrail_id`, `guardrail_version` | Baseline guardrail every model call attaches |
| `authorized_model_ids`, `inference_profile_geo` | Models the model allow-list SCP permits; inference profiles must be `<geo>.*` |
| `gateway_id`, `gateway_url`, `gateway_arn`, `gateway_role_name` | Register tools; grant the gateway role invoke on them |
| `policy_engine_id` | Cedar tool policies (null where the policy engine is unavailable, e.g. GovCloud) |
| `memory_id` | AgentCore Memory (enclave CMK, event expiry) |
| `agents_repository_url` | ECR repository `sgea-<env>-agents` for agent images |
| `token_ledger_table`, `token_timezone`, `token_per_user_daily` | Token budgets (read-only for tenants) |
| `log_retention_days` | Retention every tenant log group must use |
| `vpc_id` | Enclave VPC; the agent subnets / security groups come from the network owner |

## 2. Constraints the enclave enforces

| Constraint | Enforced by |
|---|---|
| Runtimes are VPC-only, JWT-authenticated, idle timeout <= 900 s, request-header allow-list | `agentcore-runtime` wrapper (variable validations; `PUBLIC` mode is not exposed) — SGEA-AC-RT-01..07 |
| Every model invocation carries a guardrail | SCP pack `bre-scp-04-guardrail-enforce` (deny without `bedrock:GuardrailIdentifier`) + the account-enforced baseline guardrail |
| Only authorized foundation models, only same-geo inference profiles | SCP packs `bre-scp-07-model-allowlist`, `bre-scp-03-inference-profile`; the sample's `check "model_is_authorized"` block fails earlier |
| Only allowed services and regions | SCP packs `bre-scp-02-bedrock-surface`, `bre-scp-01-region-lockdown` |
| No cross-tenant access where principal and resource both carry `sgea:tenant` | SCP pack `bre-scp-06-tenant-isolation` |
| Gateway tool calls default-deny | Policy engine in `ENFORCE` mode, or the SGEA interceptor `sgea-<env>-tool-policy` (GovCloud) |
| Tool calls past the token budget are denied, fail closed | Interceptor `sgea-<env>-tool-policy` reading `sgea-token-usage-<env>` |

The SCP / RCP layer (packs bundled into the `sgea-scp-N` / `sgea-rcp-N` policies) is present only where the enclave was deployed with `deploy_org_policies = true`
(CDK `-c sgea:deployOrgPolicies=true`) from the management account.

## 3. Procedure

1. **Agree the open items with the ISSO** before building:
   - **SGEA-KF-02 (`lambda-concurrency-check`).** Profiles composing FedRAMP Low / Moderate / High or DoD IL5 (the
     `dod-il2` profile composes FedRAMP Moderate) carry the pack parameter `ConcurrencyLimitLow = 500`, so every
     tenant Lambda needs reserved concurrency in the 500–1000 range to pass. The sample reserves 20 and is reported
     NON_COMPLIANT. Choose: (a) reserve >= 500 per function and size the quota, (b) deploy the packs with a range that
     fits your workloads, or (c) record the tenant deviation as accepted.
   - **Lambda quota headroom.** The enclave already reserves concurrency for its own functions (`MANUAL-STEPS.md`
     section 1, quota `L-B99A9384`); Lambda keeps 100 unreserved. Each tenant function adds its reservation on top:
     `aws service-quotas get-service-quota --service-code lambda --quota-code L-B99A9384 --region <region>`.
   - **Model.** The inference profile's foundation model must be in `authorized_model_ids`.
2. **Identity (JWT).** Register an OIDC app client for the agent in the organization IdP (the sample's Cognito user
   pool `sgea-<env>-sample-test-idp` is a **test IdP only**). You need the discovery URL and the client id(s).
   - Runtime inbound auth is per tenant: the wrapper's `jwt_discovery_url`, `jwt_allowed_clients`,
     `jwt_allowed_audience`.
   - The gateway authorizer is enclave-wide: `CUSTOM_JWT` when the enclave sets `agent_jwt_discovery_url` /
     `agent_jwt_allowed_clients` (CDK `jwtDiscoveryUrl` / `jwtAllowedClients`), otherwise `AWS_IAM`. Adding a client
     to the gateway is an enclave change ([change and upgrade](change-and-upgrade.md)). The sample calls an `AWS_IAM`
     gateway with SigV4.
   - Team membership comes from the claim `token_control.team_claim` (default `cognito:groups`, first value): put each
     user in exactly the group that should carry their team budget. Enforce MFA in the IdP.
3. **Execution role** (sample: `sgea-<env>-sample-agent`). Trust `bedrock-agentcore.amazonaws.com` with
   `aws:SourceAccount` and `aws:SourceArn` conditions. One customer-managed policy plus an attachment — **no inline
   policies** — scoped to: the agent image repository (`ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`;
   `ecr:GetAuthorizationToken` has no resource scoping), the runtime log groups
   `/aws/bedrock-agentcore/runtimes/*`, the exact inference profile and foundation model, `bedrock:ApplyGuardrail`
   on the enclave guardrail, the memory actions on `memory_id`, `bedrock-agentcore:InvokeGateway` on `gateway_id`,
   `kms:Decrypt` / `kms:GenerateDataKey` on `kms_key_arn`. No `*:*`, no `<service>:*`, no KMS actions on all keys.
4. **Image.** Build for `linux/arm64` with the AgentCore Runtime HTTP contract (`GET /ping`, `POST /invocations`,
   port 8080) and push to `agents_repository_url` with an immutable, content-derived tag:
   `examples/sample-agent/scripts/build_push.sh <agents_repository_url> <region>` (Finch, or `FINCH=docker`). The
   repository scans on push and is KMS-encrypted. Its lifecycle policy expires untagged images after 14 days and
   **keeps only the most recent 100 images across all tenants** — pin the images you run and tell the enclave team
   if your release cadence needs more.
5. **Tool Lambdas** (sample: `module "tool"` in `infra/main.tf`). In the agent subnets / security groups; dead-letter
   queue (SQS, encrypted with `kms_key_arn`); environment encrypted with `kms_key_arn`; X-Ray `Active`;
   reserved concurrency per step 1; log retention `log_retention_days` with `kms_key_arn`; module inline policies off
   (`attach_cloudwatch_logs_policy` / `attach_tracing_policy` / `attach_network_policy` /
   `attach_dead_letter_policy = false`) and one customer-managed policy plus `AWSLambdaVPCAccessExecutionRole` and
   `AWSXRayDaemonWriteAccess`.
6. **Register the tool on the enclave gateway.**
   1. Create a customer-managed policy allowing `lambda:InvokeFunction` on your function only and attach it to the
      enclave gateway role `gateway_role_name` (`sgea-<env>-agentcore-gateway`). This policy is reviewed in every
      [access review](access-review.md).
   2. Create the gateway target (`aws_bedrockagentcore_gateway_target`: MCP Lambda target, inline tool schema,
      `credential_provider_configuration { gateway_iam_role {} }`). Callers see the tool as `<target>___<tool>`
      (sample: `facts___enclave_facts`).
7. **Permit the tool (tool-path policy).** The gateway denies every tool not explicitly permitted.
   - Where `policy_engine_id` is set: one Cedar policy per tool in that policy engine
     (`awscc_bedrockagentcore_policy`, `validation_mode = "FAIL_ON_ANY_FINDINGS"`), principal = **exactly** your agent
     role's assumed-role ARN, action = `AgentCore::Action::"<target>___<tool>"`, resource = `gateway_arn`. A bare
     `principal is AgentCore::IamEntity` is rejected as overly permissive.
   - Where it is null (GovCloud): the rule goes into the enclave's interceptor rules (`tool_policy`, CDK
     `sgea:toolPolicy`; JSON list of `{effect, tools[], claim?, values[]}`; deny overrides allow; default deny) — an
     enclave change. Under an `AWS_IAM` gateway no JWT claims reach the interceptor, so rules match on tool name only.
8. **Runtime.** Use SGEA's wrapper from the enclave export, not a hand-written runtime: the sample links
   `infra/.sgea-modules` to `build/<profile-id>/terraform/modules` and calls `./.sgea-modules/agentcore-runtime`.
   - `name` with underscores (sample: `sgea_<env>_sample_agent`), `execution_role_arn`, `container_uri`,
     `subnet_ids` / `security_group_ids` (agent subnets), the JWT inputs from step 2.
   - `request_header_allowlist = ["Authorization"]` so the agent can read the caller's validated JWT for attribution.
   - `environment`: `SGEA_MODEL_ID`, `SGEA_GUARDRAIL_ID`, `SGEA_GUARDRAIL_VERSION`, `SGEA_MEMORY_ID`,
     `SGEA_GATEWAY_URL`.
   - `allowed_source_vpce_ids` = the enclave's `bedrock-agentcore` interface endpoint id(s) (the `enclave-network`
     module output `endpoint_ids`; not part of the root `enclave` output). Left empty — as in the sandbox sample — no
     resource policy is emitted and SGEA-AC-ID-04 is unmet.
9. **Runtime log group.** AgentCore creates `/aws/bedrock-agentcore/runtimes/<runtime-id>-DEFAULT` itself, so it
   cannot be pre-created. Apply `kms_key_arn` and `log_retention_days` right after the runtime exists (sample:
   `terraform_data.runtime_log_controls`, `aws logs associate-kms-key` + `aws logs put-retention-policy`); otherwise
   `cloudwatch-log-group-encrypted` and `cw-loggroup-retention-period-check` fail.
10. **Agent code** (sample: `app/agent.py`).
    - Call Bedrock with `guardrailConfig` = `SGEA_GUARDRAIL_ID` / `SGEA_GUARDRAIL_VERSION`; wrap user input in
      `guardContent` (system prompt and tool results are not scanned as user input). Your own guardrails may be
      added; they never replace the baseline one.
    - Token attribution: pass `requestMetadata` `sgea_user` (JWT `sub`) and `sgea_team` on every Converse call — the
      meter `sgea-<env>-token-meter` credits the ledger from the invocation logs; unattributed calls are recorded
      against the calling IAM principal. Under an `AWS_IAM` gateway, send `X-Sgea-User` / `X-Sgea-Team` on gateway
      calls; with token control on, a tool call without an identifiable user is denied.
    - Memory: `create_event` on `SGEA_MEMORY_ID` with your own `actorId` / session ids. The memory and gateway are
      enclave-shared resources without a `sgea:tenant` tag, so separation between tenants on them rests on IAM
      scoping and your ids, not on the tenant-isolation SCP.
    - Never log prompts, answers or tokens; log outcomes (the sample's `findings()` records filter types only).
11. **Tags.** Tag every tenant resource and role `sgea:tenant = <tenant>` (sample: provider `default_tags`, also
    `sgea:profile = <profile-id>`). The tenant-isolation SCP only applies where both principal and resource carry the
    tag; untagged resources are not protected by it.
12. **Validate** in non-production with the e2e checks adapted to your agent (`scripts/e2e_test.py`):
    authenticated call answered through the guardrail, tool call allowed by the tool policy, PII prompt blocked,
    contextual PII masked, usage credited to the ledger, over-budget tool calls denied, unauthenticated call
    rejected (401 / 403).

## 4. Token budgets

Budgets are **enclave-wide** values in the profile's `token_control` (`per_user_daily_tokens`,
`per_team_monthly_tokens`, `default_timezone`, `fail_closed_hours`, `team_claim`); a tenant is "assigned" a budget
by its users' team claim, not by a per-tenant setting. Ledger items: `pk=user#<sub>` / `sk=day#YYYY-MM-DD` and
`pk=team#<team>` / `sk=month#YYYY-MM`, attribute `tokens`. Only the **gateway tool path** is enforced: direct model
calls are metered but not blocked. When the meter heartbeat (`pk=meter`, `sk=heartbeat`) is older than
`fail_closed_hours`, or the ledger is unreadable, every tool call is denied. Changing a budget is a profile change
([change and upgrade](change-and-upgrade.md)).

## 5. AWS Config rules that evaluate tenant resources

The enclave's conformance packs evaluate the whole account, so tenant resources are in scope. Which rules apply
depends on the composed packs (`docs/frameworks/<baseline>.md`, `docs/CONTROL-COVERAGE.md`).

| Tenant resource | Rules (where the composed packs include them) |
|---|---|
| Lambda functions | `lambda-concurrency-check` (SGEA-KF-02), `lambda-inside-vpc`, `lambda-dlq-check`, `lambda-function-public-access-prohibited` |
| IAM roles / policies | `iam-no-inline-policy-check`, `iam-policy-no-statements-with-admin-access`, `iam-policy-no-statements-with-full-access`, `iam-customer-policy-blocked-kms-actions` |
| Log groups | `cloudwatch-log-group-encrypted`, `cw-loggroup-retention-period-check` |
| S3 buckets | `s3-bucket-ssl-requests-only`, `s3-default-encryption-kms`, `s3-bucket-server-side-encryption-enabled`, `s3-bucket-versioning-enabled`, `s3-bucket-logging-enabled`, `s3-bucket-default-lock-enabled`, `s3-bucket-level-public-access-prohibited`, `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`, `s3-resources-protected-by-backup-plan` |
| DynamoDB tables | `dynamodb-table-encrypted-kms`, `dynamodb-pitr-enabled`, `dynamodb-in-backup-plan`, `dynamodb-resources-protected-by-backup-plan`, `dynamodb-autoscaling-enabled` |
| SNS topics / secrets | `sns-encrypted-kms`; `secretsmanager-using-cmk`, `secretsmanager-rotation-enabled-check` |
| Security groups | `restricted-ssh`, `restricted-common-ports`, `vpc-sg-open-only-to-authorized-ports` |
| ElastiCache (allowed for tenants) | `elasticache-redis-cluster-automatic-backup-check` (disposition `tenant`) |

`sgea check` reports per-app SGEA controls as `N/A-APP` on the enclave plan; enforce them in the tenant's own IaC
review.

## 6. Onboarding checklist

| # | Item | Evidence | Done |
|---|---|---|---|
| 1 | ISSO decision on SGEA-KF-02 (reserved concurrency) recorded | Decision record | [ ] |
| 2 | Lambda quota headroom for tenant reservations confirmed | `get-service-quota` output | [ ] |
| 3 | Model's foundation model in `authorized_model_ids`; inference profile in `inference_profile_geo` | Plan passes `model_is_authorized` | [ ] |
| 4 | OIDC app client in the organization IdP; MFA enforced; team groups defined | IdP configuration | [ ] |
| 5 | Gateway client registered by the enclave team (if the gateway is `CUSTOM_JWT`) | Enclave change record | [ ] |
| 6 | Execution role: trust conditions, one customer-managed policy, scoped resources, no inline policy | Policy JSON | [ ] |
| 7 | Image `linux/arm64`, immutable tag, in `sgea-<env>-agents`, scan clean | ECR scan result | [ ] |
| 8 | Tool Lambdas in VPC, DLQ (KMS), env KMS, X-Ray, reserved concurrency, retention + KMS, no inline policy | Plan / Config results | [ ] |
| 9 | Gateway-role invoke policy scoped to the tenant's functions only | Policy JSON | [ ] |
| 10 | Gateway targets registered; Cedar policy (or interceptor rule) per tool, exact principal | Policy list | [ ] |
| 11 | Runtime via the `agentcore-runtime` wrapper; `allowed_source_vpce_ids` set | Plan | [ ] |
| 12 | Runtime log group KMS + retention applied | `describe-log-groups` | [ ] |
| 13 | Agent attaches the guardrail, uses `guardContent`, passes `sgea_user` / `sgea_team` | Code review | [ ] |
| 14 | All resources and roles tagged `sgea:tenant` (and `sgea:profile`) | Tag report | [ ] |
| 15 | No prompts / tokens / answers in logs | Code review | [ ] |
| 16 | e2e checks pass in non-production | Test output | [ ] |
| 17 | Conformance packs show no new NON_COMPLIANT tenant resources beyond accepted deviations | Pack results | [ ] |
| 18 | Tenant added to the access-review inventory | Access-review record | [ ] |
