# ADR 0003 — Token budgets bound model calls (token breaker)

Status: accepted (2026-10-27). Both engines implement this with the same names. Names use `<env>` (Terraform `var.env`, CDK `sgea:env`).

## Context

SGEA-TC-01 enforces the per-user daily and per-team monthly token budgets in the AgentCore gateway interceptor, so an over-budget caller loses **tool calls** only. The tenant agent's runtime role can still call Bedrock directly, so a team past its budget keeps spending on model calls. Constraints:

- Tenant runtime roles belong to the tenant apps, not the enclave.
- The token meter runs in the enclave VPC, which has no NAT and no IAM endpoint, so it cannot call IAM.
- Bedrock foundation models and inference profiles have no resource policies, so the denial must sit on the caller's identity.
- IAM cannot see `requestMetadata` (`sgea_user`), so IAM can bound a role, not a user.

Options considered:
- **A proxy for model calls.** It enforces per user, before the call. But it adds a service to the data path that sees every prompt and response (PHI), with its own logging, scaling and availability, and it only works if direct Bedrock access is removed from tenant roles.
- **The meter editing a policy document.** The meter would need `iam:CreatePolicyVersion`, so a compromised meter could write an Allow into a policy attached to tenant roles.
- **Tagging tenant roles.** Tag changes are not reliably visible to existing sessions, and tenant IaC that owns tags removes the tag on its next apply.

## Decision

Add a **model-call breaker** to the token-control layer (Terraform `modules/token-control`, CDK `Governance`). It acts per team and per runtime role, and it is on by default where the meter runs and a team budget is set (`token_control.model_enforce`, default `true`).

**Static deny policy.** The enclave creates the customer-managed policy `sgea-<env>-token-budget-exhausted`, whose only statement is a Deny of `bedrock:InvokeModel*` and `bedrock:RetrieveAndGenerate*` on `*`. Its content never changes at run time.

**Trip.** When the meter credits a team's month to at least `per_team_monthly_tokens`, it reads the calling role from the invocation log (`identity.arn`, `assumed-role/<role>/…`). It then writes a trip record `pk=breaker, sk=role#<role>` (`team`, `month`) to the ledger, once per role and month, and puts an event on the default bus: source `sgea.token-meter`, detail-type `SGEA Token Budget Breaker`, detail `{"roles": [{"role", "team", "action"}]}`. If the event fails, the batch still counts as credited and the heartbeat retries; the meter never fails a credited batch, which would be re-delivered and credited twice.

**Apply.** The EventBridge rule `sgea-<env>-token-breaker` starts the Step Functions state machine `sgea-<env>-token-breaker` (STANDARD, JSONata, no Lambda). Each request runs these steps:
1. Read the trip record (consistent read). It **acts only on the ledger**: a forged or stale event does nothing.
2. Attach only when the record is active and names the same team, and the role's tag `sgea:team` equals that team (`iam:GetRole`). Then `iam:AttachRolePolicy`.
3. Detach only when the record is gone or marked released. Then `iam:DetachRolePolicy`.
4. Ignore unknown roles.

**Release.** The 15-minute heartbeat re-asserts every active trip, which repairs detachments by tenant IaC. It releases a trip in two steps, mark released + detach, then detach + forget, when any of these holds:
- the month rolled over;
- the team is back under the budget;
- an override item `pk=override, sk=team#<team>#month#YYYY-MM` exists.

**Least privilege.**
- The meter may `events:PutEvents` only on the default bus with `events:source` = `sgea.token-meter`.
- The state machine role `sgea-<env>-token-breaker` may:
  - `dynamodb:GetItem` on the ledger and `kms:Decrypt` on the enclave key;
  - `iam:GetRole` on roles;
  - `iam:AttachRolePolicy` only with `iam:PolicyARN` = the deny policy and only on roles that carry `aws:ResourceTag/sgea:team`;
  - `iam:DetachRolePolicy` only with that policy ARN.
- The state machine role is explicitly denied both actions on `sgea-*-break-glass`. Its CloudWatch Logs delivery and X-Ray actions are account-level APIs.
- The worst a compromised breaker can do is deny model calls to tagged roles.
- The events role `sgea-<env>-token-breaker-events` may only `states:StartExecution` on the state machine.

**Observability.** The state machine logs at `ERROR` level without execution data to `/aws/vendedlogs/states/sgea-<env>-token-breaker`, encrypted with the enclave CMK and kept for the pack retention, and has X-Ray tracing on. The alarm `sgea-<env>-token-breaker-failures` (`AWS/States` `ExecutionsFailed` >= 1 in 5 min) goes to the security-alarm topic. Every attach and detach is a CloudTrail event; it also raises `sgea-<env>-ct-iam-policy-changes` (ADR 0002).

**Service.** Step Functions becomes a `services.allow` id (`stepfunctions`, IAM prefix `states`). It is authorized at FedRAMP Moderate and High, DoD IL2, IL4 and IL5, and is HIPAA eligible (AWS Services in Scope, catalog rebuild 2026-10-27). With `model_enforce` on, `sgea resolve` requires `eventbridge` and `stepfunctions` in `services.allow`.

**Control.** SGEA-TC-03 (`aws_sfn_state_machine.role_arn` / `AWS::StepFunctions::StateMachine.RoleArn`) is checked by `sgea check`. Tenant requirement TR-26: tag each runtime role `sgea:team`, one team per role, and do not detach the deny policy.

## Consequences

- **What it bounds.** Model calls are bounded per team, per runtime role. Per-user daily budgets still bound only tool calls.
- **Shared roles.** A role that serves several teams cannot carry one `sgea:team` value, so it stays bounded on the tool path only.
- **Overshoot.** Enforcement lags the invocation log by minutes: log delivery, the meter, EventBridge, Step Functions and IAM propagation. A burst can overshoot the budget. This is a breaker, not a hard quota.
- **Per-user hard limits.** A per-user model-call limit before the call still needs a proxy; that is out of scope.
- **Tenant IaC.** Tenant IaC with exclusive policy-attachment management detaches the deny policy on apply. The next heartbeat re-attaches it within 15 minutes; TR-26 asks tenants to exclude the attachment.
- **Cost.** Step Functions STANDARD state transitions per trip and per heartbeat while a trip is active: a few cents a month.
- **Validation.** The sandbox e2e test adds two checks: an over-budget team's model calls are denied, and the breaker is released once the team is back under budget. Sandbox (HITRUST, 2026-10-27): 9/9 on Terraform and CDK, teardown clean; the other commercial profiles last ran the 7-check test.
