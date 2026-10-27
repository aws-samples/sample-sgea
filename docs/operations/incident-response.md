# Incident response — enclave signals and playbooks

One playbook for each signal the enclave emits or records. Names use `<env>` (the Terraform `env` variable /
CDK `-c sgea:env`), `<account>`, `<region>` (primary) and `<replica-region>`. Every alarm, topic, function, table,
log group and key-policy statement below comes from the emitted IaC (`emitters/terraform_emitter.py`,
`emitters/cdk_app/`, `emitters/lambda/`); both engines use the same names unless a row says otherwise.

Use read-only credentials for triage. Containment and recovery steps change production resources: they need the
incident lead's approval and a change record. Re-apply the IaC afterwards so the enclave matches its code and its
AWS Config evidence again.

> **Sensitive data.** The Bedrock model-invocation logs (`/sgea/<env>/bedrock/model-invocations`, and
> `s3://sgea-<env>-logs-<account>-<region>/bedrock/`) and the token-meter dead-letter queue hold prompt and response
> text. Limit who may query them. Put counts, user ids and time windows in tickets, not the text.

## Signal inventory

| # | Signal | Source in the IaC | Where it goes | Playbook |
|---|---|---|---|---|
| A1 | Alarm `sgea-<env>-tool-policy-errors`: Lambda `Errors` > 0 in 5 min on `sgea-<env>-tool-policy` | `agentcore-platform` (deployed when the interceptor is: GovCloud tool-path stand-in or token budgets) | `sgea-<env>-security-alarms` | [3](#3-gateway-interceptor-denies-every-tool-call) |
| A2 | Alarm `sgea-<env>-token-meter-errors`: `Errors` > 0 in 5 min on `sgea-<env>-token-meter` | `token-control` (Terraform) / `governance` (CDK) | `sgea-<env>-security-alarms` | [3](#3-gateway-interceptor-denies-every-tool-call) |
| A3 | Alarm `sgea-<env>-token-meter-silent`: `Invocations` < 1 for 2 x 15 min, missing data = breaching | as A2 | `sgea-<env>-security-alarms` | [3](#3-gateway-interceptor-denies-every-tool-call) |
| A4 | Alarm `sgea-<env>-token-breaker-failures`: `AWS/States` `ExecutionsFailed` >= 1 in 5 min on `sgea-<env>-token-breaker` (ADR 0003) | `token-control` / `governance`, where `token_control.model_enforce` is on | `sgea-<env>-security-alarms` | [2](#2-token-budget-exhausted-for-a-user-or-team) |
| S1 | SNS `sgea-<env>-log-store-events`: `s3:ObjectRemoved:*` from the log store, the AWS Config store and the access-log sink (primary region; the replica buckets do not notify) | `enclave-logging` / `hardened-bucket` | subscribers you add | [5](#5-unexpected-object-deletion-on-the-log-stores) |
| L1 | Interceptor decision log: one JSON line per `tools/call` (`sgea`, `decision`, `reason`, `tool`, `user`, `team`, `client_id`; never the token) | `emitters/lambda/tool_policy_interceptor.py` | `/aws/lambda/sgea-<env>-tool-policy` | [2](#2-token-budget-exhausted-for-a-user-or-team), [3](#3-gateway-interceptor-denies-every-tool-call), [7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt) |
| L2 | Guardrail interventions: the caller sees `Blocked by enclave guardrail.` | `bedrock-guardrail` (`blocked_input_messaging` / `blocked_outputs_messaging`) | model-invocation logs | [1](#1-guardrail--pii-block-spike) |
| L3 | CloudTrail `sgea-<env>` (multi-region, log-file validation, enclave CMK; Bedrock / AgentCore / S3 data events per profile) and AWS Config recorder / delivery channel `sgea-<env>` | `enclave-logging`, `config-conformance` | log store, `/sgea/<env>/cloudtrail`, Config store | [4](#4-cloudtrail-or-aws-config-delivery-stopped) |
| G1 | GuardDuty detector (`FIFTEEN_MINUTES` publishing) and Security Hub with NIST SP 800-53 Rev 5 | `security-services` (unless `create_guardduty` / `create_securityhub` = false) | GuardDuty / Security Hub consoles, your SIEM; high-severity findings also routed to `sgea-<env>-security-alarms` by E1 / E2 | [6](#6-guardduty-high-severity-finding) |
| C1 | Alarms `sgea-<env>-ct-cloudtrail-changes`, `-ct-config-changes`, `-ct-kms-key-disable-or-delete`, `-ct-iam-policy-changes`, `-ct-s3-bucket-policy-changes`, `-ct-organizations-changes`: CloudTrail metric filters `sgea-<env>-ct-<name>` (namespace `SGEA/<env>/CloudTrail`), Sum >= 1 in 5 min, missing data = not breaching | `enclave-monitoring` (`manage_monitoring` / CDK `sgea:manageMonitoring`, default on), filters on `/sgea/<env>/cloudtrail` | `sgea-<env>-security-alarms` | [8](#8-audit-trail-or-security-configuration-tampering) |
| C2 | Alarms `sgea-<env>-ct-security-group-changes`, `-ct-nacl-changes`, `-ct-network-gateway-changes`, `-ct-route-table-changes`, `-ct-vpc-changes` | as C1 | `sgea-<env>-security-alarms` | [9](#9-network-configuration-change) |
| C3 | Alarms `sgea-<env>-ct-root-usage`, `-ct-console-no-mfa`, `-ct-console-auth-failures`, `-ct-unauthorized-api` | as C1 | `sgea-<env>-security-alarms` | [10](#10-root-use-console-sign-in-without-mfa-failed-sign-ins-unauthorized-api-calls) |
| C4 | Alarm `sgea-<env>-ct-break-glass-assumed`: `AssumeRole` on `sgea-<env>-break-glass` | as C1, only with `create_break_glass_role` (CDK `sgea:createBreakGlassRole`) | `sgea-<env>-security-alarms` | [11](#11-break-glass-role-assumed) |
| H1 | Alarms `sgea-<env>-bedrock-throttles` (`AWS/Bedrock` `InvocationThrottles`, account, Sum >= 10 in 2 of 2 x 5 min), `-bedrock-server-errors` (`InvocationServerErrors` Sum >= 5 in 5 min), `-bedrock-invocation-log-delivery` (`ModelInvocationLogsCloudWatchDeliverySuccess` Minimum < 1 over 15 min; only where model-invocation logging is on) | `enclave-monitoring` | `sgea-<env>-security-alarms` | [15](#15-bedrock-or-gateway-service-health) |
| H2 | Alarm `sgea-<env>-guardrail-interventions`: `AWS/Bedrock/Guardrails` `InvocationsIntervened` on the baseline guardrail ARN and version, Sum >= `guardrail_intervention_threshold` (CDK `sgea:guardrailInterventionThreshold`, default 50) over 15 min | `enclave-monitoring` | `sgea-<env>-security-alarms` | [1](#1-guardrail--pii-block-spike) |
| H3 | Alarms `sgea-<env>-gateway-system-errors` (`AWS/Bedrock-AgentCore` `SystemErrors`, `Operation` = InvokeGateway, `Protocol` = MCP, `Resource` = the enclave gateway, Sum >= 5 in 5 min) and `-gateway-throttles` (`Throttles`, same dimensions, Sum >= 10 in 2 of 2 x 5 min) | `enclave-monitoring`, only where the gateway exists | `sgea-<env>-security-alarms` | [15](#15-bedrock-or-gateway-service-health) |
| E1 | EventBridge rule `sgea-<env>-evt-guardduty`: `GuardDuty Finding`, severity >= 7 | `enclave-monitoring` (rules `sgea-<env>-evt-<name>`, default event bus) | `sgea-<env>-security-alarms` (the raw event JSON) | [6](#6-guardduty-high-severity-finding) |
| E2 | Rules `sgea-<env>-evt-securityhub` (new HIGH / CRITICAL `Security Hub Findings - Imported`), `-evt-inspector` (HIGH / CRITICAL `Inspector2 Finding`), `-evt-access-analyzer` (`Access Analyzer Finding`, status ACTIVE; only when an analyzer is created) | as E1; analyzers `sgea-<env>-external-access` (`create_access_analyzer`, default on) and `sgea-<env>-unused-access` (`create_unused_access_analyzer`, default off) | `sgea-<env>-security-alarms` | [12](#12-security-hub-inspector-or-access-analyzer-finding) |
| E3 | Rules `sgea-<env>-evt-config-compliance` (`Config Rules Compliance Change` to NON_COMPLIANT) and `-evt-stack-drift` (CDK only: `CloudFormation Drift Detection Status Change`, DRIFTED, from the daily schedule `sgea-<env>-drift-detect`) | as E1 | `sgea-<env>-security-alarms` | [13](#13-aws-config-rule-non-compliant-or-stack-drift) |
| E4 | Rules `sgea-<env>-evt-backup` (backup, copy or restore job FAILED / ABORTED / EXPIRED) and `-evt-secret-rotation` (Secrets Manager `RotationFailed`) | as E1 | `sgea-<env>-security-alarms` | [14](#14-backup-job-or-secret-rotation-failed) |
| B1 | Budget `sgea-<env>-monthly-cost` (ACTUAL > 80 %, FORECASTED > 100 % of `monthly_budget_usd` / CDK `sgea:monthlyBudgetUsd`; off at 0) and Cost Anomaly Detection subscription `sgea-<env>-anomalies` on monitor `sgea-<env>-services` (impact >= USD 100; opt-in `create_cost_anomaly_monitor` / `sgea:createCostAnomalyMonitor`) | `enclave-monitoring`, commercial partition only | `sgea-<env>-security-alarms` | [16](#16-budget-or-cost-anomaly-alert) |

All `C`, `H`, `E` and `B` signals come from the `enclave-monitoring` layer (Terraform module `modules/enclave-monitoring`, CDK construct `EnclaveMonitoring`; design in `docs/adr/0002-enclave-monitoring.md`). Plan for these limits:

- The IaC creates **no subscriptions** on `sgea-<env>-security-alarms` or `sgea-<env>-log-store-events`. Subscribing the security team is a post-deploy step (`MANUAL-STEPS.md`). Both topics are encrypted with the enclave CMK. An SQS or Lambda subscriber needs `kms:Decrypt` on that key.
- **Delivery depends on the enclave CMK.** If the key is disabled or pending deletion, no alarm or event reaches the topic's subscribers, including `sgea-<env>-ct-kms-key-disable-or-delete` for the enclave key itself, and CloudTrail stops delivering too. Keep the daily key check in [key and secret management](key-and-secret-management.md).
- Alarm messages are CloudWatch alarm JSON (`AlarmName`, `NewStateReason`, `StateChangeTime`). Event rules deliver the raw event JSON, with no input transformer.
- Signals depend on toggles and on the profile: `manage_monitoring` = false removes the whole layer; the health alarms H1 log delivery and H3 exist only where model-invocation logging or the gateway exist; `-evt-access-analyzer` only with an analyzer; `-evt-stack-drift` only in CDK (Terraform: a scheduled `terraform plan -detailed-exitcode` in your pipeline, see [change and upgrade](change-and-upgrade.md)); B1 only when turned on, and never in `aws-us-gov` (billing is in the commercial payer account).
- CloudTrail / AWS Config delivery failures that are not API calls (a broken key or bucket policy, a delivery-role change through another path) raise no direct alarm. They show as a Config compliance change (E3) or in the scheduled check of [playbook 4](#4-cloudtrail-or-aws-config-delivery-stopped).
- Alert volume: the CIS-style filters (C1–C3) fire on every legitimate IaC apply that touches IAM, buckets or the network, and `-ct-unauthorized-api` and `-evt-config-compliance` are noisy in a busy account. Match alerts against the change calendar first; tune the guardrail threshold or turn off parts of the layer through the toggles (ADR 0002) rather than deleting rules by hand.
- The monitoring layer is new in this release: it deploys and tears down on both engines (HITRUST sandbox, 2026-10-27), but alarm and event delivery to the topic were not exercised there; test your subscription once after deploy.
- Alarm INSUFFICIENT_DATA actions are present only when the composed packs require them (`alarm_insufficient_data_action`, from the pack parameters of `cloudwatch-alarm-action-check`).

Check that the alarms exist and see their state:

```bash
aws cloudwatch describe-alarms --alarm-name-prefix sgea-<env>- \
    --query 'MetricAlarms[].[AlarmName,StateValue,StateUpdatedTimestamp]' --output table
aws events list-rules --name-prefix sgea-<env>-evt- --query 'Rules[].[Name,State]' --output table
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:<region>:<account>:sgea-<env>-security-alarms
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:<region>:<account>:sgea-<env>-log-store-events
```

To find the CloudTrail events behind any `sgea-<env>-ct-<name>` alarm, reuse the alarm's own filter pattern (used in playbooks 8–11):

```bash
P=$(aws logs describe-metric-filters --log-group-name /sgea/<env>/cloudtrail --filter-name-prefix sgea-<env>-ct-<name> \
    --query 'metricFilters[0].filterPattern' --output text)
aws logs filter-log-events --log-group-name /sgea/<env>/cloudtrail --start-time <epoch-ms> --filter-pattern "$P" \
    --query 'events[].message' --output json \
  | jq -r '.[] | fromjson | [.eventTime, .eventName, .userIdentity.arn, .sourceIPAddress, .errorCode] | @tsv'
```

(GovCloud: partition `aws-us-gov` in every ARN.)

---

## 1. Guardrail / PII block spike

**Trigger.** Alarm `sgea-<env>-guardrail-interventions` (H2): the baseline guardrail intervened at least `guardrail_intervention_threshold` times (default 50) in 15 minutes. Or users or a tenant team report many `Blocked by enclave guardrail.` answers, or your own query on the invocation logs (step 2) shows more blocks than usual.

The alarm watches the guardrail ARN and version the enclave deployed; a redeploy that creates a new guardrail version moves the alarm to it. Tune the threshold with `guardrail_intervention_threshold` (CDK `sgea:guardrailInterventionThreshold`) once you know the normal rate, not by editing the alarm.

**Likely causes**

- Real PII / PHI in prompts. Hard identifiers are BLOCKed. Contextual entities (for example an address) are
  ANONYMIZEd, not blocked.
- Prompt-injection or jailbreak attempts (prompt-attack filter), or probing of denied topics.
- False positives. In the sandbox (2026-10-21) the HIGH-strength prompt-attack filter blocked a benign prompt at
  LOW confidence.
- A new tenant app sends system prompts or tool results as user content. The account-enforced guardrail guards
  every user message (`messages: COMPREHENSIVE`) and the system prompt only where it is tagged (`system: SELECTIVE`).
- A redeploy created a new immutable guardrail version from a changed profile.

**Triage**

1. Look up the guardrail in use: `terraform output -json enclave` (Terraform) or the `Enclave` stack output
   (CDK) gives `guardrail_id` and `guardrail_version`. Then run
   `aws bedrock get-guardrail --guardrail-identifier <id> --guardrail-version <version>`.
2. Count the blocks over time. Run this in CloudWatch Logs Insights on `/sgea/<env>/bedrock/model-invocations`:
   ```
   filter @message like "Blocked by enclave guardrail."
   | stats count() as blocks by bin(1h), requestMetadata.sgea_user, requestMetadata.sgea_team
   ```
   `sgea_user` / `sgea_team` are the request metadata the tenant runtime sets from the caller's validated JWT (the
   token meter uses the same fields). Calls without them come from apps that do not attribute usage.
3. Decide whether it is one user, one team, one app or everyone:
   - One user or team usually means user behavior or misuse.
   - Every app at once usually means a guardrail or profile change. Check CloudTrail for `UpdateGuardrail` /
     `CreateGuardrailVersion`.
4. Open a few blocked records (authorized analyst only). The guardrail assessment in each record shows which policy
   intervened: content filter, PII entity or denied topic.

**Containment**

- Misuse by one identity: go to [playbook 7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt).
- PII from an upstream feed (a tool or knowledge-base source): stop that tenant app's ingestion until the data
  owner has reviewed it.
- Do not turn off or bypass the guardrail. It is enforced account-wide, and where the org policies are deployed the
  `DenyInvokeWithoutGuardrail` SCP denies inference without it.

**Recovery**

1. For confirmed false positives, change the profile's `guardrails` block (filter strength, `pii.action`,
   `pii.contextual_action`, denied topics). Then run `sgea export`, `sgea verify` and `sgea check`, and redeploy. That
   creates a new guardrail version. Get ISSO approval for the change and record it.
2. Do not edit the guardrail in the console. Control decisions live only in the resolved profile, and a console
   edit is drift against the evidence pack.

**Evidence to keep:** block counts per hour and per user, guardrail id and version JSON, CloudTrail events for
guardrail changes, and the approval for any profile change.

**Controls:** SI-4, SI-15, AC-4, AU-6, IR-4.

---

## 2. Token budget exhausted for a user or team

**Trigger.** A tool call returns JSON-RPC error `-32003` with
`Tool call denied by enclave token-budget: per-user daily token budget exhausted` (or
`per-team monthly token budget exhausted`); or, for a team past its monthly budget, the team's model calls fail with `AccessDeniedException` because the token breaker (ADR 0003) attached `sgea-<env>-token-budget-exhausted` to its `sgea:team`-tagged runtime role. This is the control working, so there is no alarm; `sgea-<env>-token-breaker-failures` (A4) fires only when the breaker itself fails. Per-user budgets gate gateway tool calls only; per-team budgets gate tool calls and, through the breaker, model calls.

**Likely causes:** legitimate heavy use; an agent stuck in a tool-call loop; someone else using the user's token
([playbook 7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt)); many users sharing one team claim
(`team_claim`, default `cognito:groups`, first value); a budget set too low for the workload.

**Triage**

1. Find the denials:
   ```bash
   aws logs filter-log-events --log-group-name /aws/lambda/sgea-<env>-tool-policy --start-time <epoch-ms> \
       --filter-pattern '{ $.reason = "per-user daily token budget exhausted" }' --query 'events[].message'
   ```
2. Read the ledger. The keys are `pk=user#<sub>`, `sk=day#YYYY-MM-DD` and `pk=team#<team>`, `sk=month#YYYY-MM`.
   Dates are in the profile's `token_control.default_timezone`.
   ```bash
   aws dynamodb get-item --table-name sgea-token-usage-<env> --consistent-read \
       --key '{"pk":{"S":"user#<sub>"},"sk":{"S":"day#<YYYY-MM-DD>"}}'
   ```
3. Read the configured budgets (the environment is encrypted with the enclave CMK, so you need `kms:Decrypt`):
   ```bash
   aws lambda get-function-configuration --function-name sgea-<env>-tool-policy \
       --query 'Environment.Variables.[PER_USER_DAILY_TOKENS,PER_TEAM_MONTHLY_TOKENS,TOKEN_TIMEZONE]'
   ```
4. See where the tokens went. Run this Logs Insights query on `/sgea/<env>/bedrock/model-invocations`:
   ```
   filter requestMetadata.sgea_user = "<sub>"
   | stats sum(input.inputTokenCount + output.outputTokenCount) as tokens, count() as calls by bin(15m)
   ```
   Usage without `sgea_user` is credited to `principal:<IAM ARN>` (the meter's fallback), not to a user.

5. For a team: see which roles the breaker holds and whether the deny policy is attached:
   ```bash
   aws dynamodb query --table-name sgea-token-usage-<env> --consistent-read \
       --key-condition-expression 'pk = :p' --expression-attribute-values '{":p":{"S":"breaker"}}'
   aws iam list-entities-for-policy --policy-arn arn:<partition>:iam::<account>:policy/sgea-<env>-token-budget-exhausted
   aws stepfunctions list-executions --state-machine-arn arn:<partition>:states:<region>:<account>:stateMachine:sgea-<env>-token-breaker --max-results 10
   ```
   A trip with no attachment means the role is not tagged `sgea:team` = that team (TR-26), or the tenant's IaC detached it (the next 15-minute heartbeat re-attaches); a failed execution is A4.

**Containment:** if the usage is not the user's, go to playbook 7. For a runaway agent, have the tenant team stop the
session or app.

**Recovery**

- The user budget resets at the next day in `TOKEN_TIMEZONE`. The team budget resets at the next month.
- To raise a budget, change `token_control.per_user_daily_tokens` / `per_team_monthly_tokens` in the profile,
  re-export and redeploy. The interceptor reads its budgets from its environment.
- The breaker releases a team on the first heartbeat after month rollover or after a redeploy that raises its budget (two heartbeats: mark released, then forget), so allow up to 30 minutes.
- Emergency release for the rest of the month (approved by the ISSO / budget owner): write an override item, then wait for the next heartbeat (or invoke the meter with an empty event twice):
  ```bash
  aws dynamodb put-item --table-name sgea-token-usage-<env> \
      --item '{"pk":{"S":"override"},"sk":{"S":"team#<team>#month#<YYYY-MM>"},"by":{"S":"<ticket>"}}'
  aws lambda invoke --function-name sgea-<env>-token-meter --payload '{}' /dev/null
  ```
  Do not detach the policy by hand without the override: the next heartbeat attaches it again. Delete the override item to restore enforcement.
- Do not edit or delete ledger usage items. They are the usage record (PITR on, covered by the backup plan).

**Evidence to keep:** the deny log lines, the ledger item, the per-user token query, the breaker trip / override items and the CloudTrail `AttachRolePolicy` / `DetachRolePolicy` events by `sgea-<env>-token-breaker`, and the approval for any budget change or override.

**Controls:** SC-6, AC-3, AU-6, SI-4.

---

## 3. Gateway interceptor denies every tool call

**Trigger.** Every `tools/call` returns `-32003`, or the e2e "tool path" check fails. Alarms A1–A3 may fire,
**but a deny is not a Lambda error.** A fail-closed denial is logged with its reason. Only crashes and timeouts
raise `sgea-<env>-tool-policy-errors`. In a sandbox run (2026-10-16), fresh CDK enclaves denied every call with
`token meter heartbeat stale (fail closed)` until the meter first ran on its 15-minute schedule. Both engines now
invoke the meter once at deploy (Terraform `aws_lambda_invocation.token_meter_first_heartbeat`, CDK
`Custom::SgeaMeterHeartbeat`).

**Likely causes: find the `reason` in the interceptor log**

| `reason` | Control | Meaning | Look at |
|---|---|---|---|
| `token meter heartbeat stale (fail closed)` | token-budget | The ledger item `pk=meter`, `sk=heartbeat` is older than `FAIL_CLOSED_HOURS` (profile `fail_closed_hours`, default 4) or missing | Meter health (steps 3–5) |
| `token ledger unavailable (fail closed): <Exception>` | token-budget | `GetItem` on `sgea-token-usage-<env>` failed | Key state, DynamoDB gateway endpoint and routes, IAM |
| `caller identity unknown (token budget fails closed)` | token-budget | No `sub` claim (CUSTOM_JWT), or no `X-Sgea-User` header (AWS_IAM gateway auth) | The tenant app's identity forwarding |
| `no allow rule (default deny)` | tool-policy | Interceptor tool-path mode only (`TOOL_POLICY_ENFORCE=true`, where the AgentCore policy engine is unavailable, for example GovCloud). The default `tool_policy` is `[]`, which denies every call | The `tool_policy` rules |
| `explicit deny` | tool-policy | A deny rule matched (deny overrides allow) | The `tool_policy` rules |
| no DENY line, but calls still denied | Cedar policy engine `sgea_<env>_tool_policy` (`ENFORCE`) | The tool has no permit policy (the sample tenant adds one: `permit_facts_tool`) | Policies on the engine |

**Triage**

1. Read the reasons:
   ```bash
   aws logs filter-log-events --log-group-name /aws/lambda/sgea-<env>-tool-policy --start-time <epoch-ms> \
       --filter-pattern '{ $.decision = "DENY" }' --query 'events[].message'
   ```
2. Check the heartbeat. `at` is epoch seconds:
   ```bash
   aws dynamodb get-item --table-name sgea-token-usage-<env> --consistent-read \
       --key '{"pk":{"S":"meter"},"sk":{"S":"heartbeat"}}'
   ```
3. Check meter health: alarm state (above), the schedule, the logs and the dead-letter queue.
   ```bash
   aws events describe-rule --name sgea-<env>-token-meter-heartbeat --query State
   aws logs tail /aws/lambda/sgea-<env>-token-meter --since 2h
   aws sqs get-queue-attributes --attribute-names ApproximateNumberOfMessages \
       --queue-url "$(aws sqs get-queue-url --queue-name sgea-<env>-token-meter-dlq --query QueueUrl --output text)"
   ```
4. Check the key state. It must be `Enabled`, because the ledger, the function environment and the logs use it:
   `aws kms describe-key --key-id alias/sgea-<env> --query KeyMetadata.KeyState`. If it is `PendingDeletion` or
   `Disabled`, see `key-and-secret-management.md`.
5. Check the network. The meter and the interceptor run in the agent subnets and reach DynamoDB through the
   enclave's DynamoDB gateway endpoint (`enclave-network`). Confirm the endpoint is still on those subnets' route
   tables.

**Containment.** None needed. Fail-closed is the safe state (SC-24). Do not remove the interceptor or raise
`fail_closed_hours` to restore service without a recorded risk decision.

**Recovery**

1. Fix the cause (key, route, rule, identity forwarding, or tool policy through the profile and a redeploy).
2. Write a heartbeat now (the same call the deploy makes):
   ```bash
   aws lambda invoke --function-name sgea-<env>-token-meter --cli-binary-format raw-in-base64-out \
       --payload '{"source":"sgea-operator"}' /tmp/sgea-meter.json
   ```
3. Re-read the heartbeat item, then make one tool call. The interceptor log should show `ALLOW`.
4. While the meter was down, failed log deliveries went to `sgea-<env>-token-meter-dlq`, so usage in that window was
   under-credited. Record the window. The DLQ messages contain invocation-log records, so treat them as sensitive.

**Evidence to keep:** the deny lines, the heartbeat item before and after, alarm history
(`aws cloudwatch describe-alarm-history --alarm-name sgea-<env>-token-meter-silent`), the DLQ depth, and the root
cause.

**Controls:** SC-24, SI-4, IR-4, AU-6.

---

## 4. CloudTrail or AWS Config delivery stopped

**Trigger.** An API call that stops or changes the trail or the recorder raises `sgea-<env>-ct-cloudtrail-changes` or `sgea-<env>-ct-config-changes` ([playbook 8](#8-audit-trail-or-security-configuration-tampering)); disabling or scheduling deletion of a key raises `sgea-<env>-ct-kms-key-disable-or-delete`. Delivery failures without such a call (key, bucket policy or delivery role broken) have no direct alarm. They show up as a non-compliant conformance-pack rule (`cloudtrail-enabled`, `multi-region-cloudtrail-enabled`, `cloud-trail-cloud-watch-logs-enabled`, `cloud-trail-log-file-validation-enabled`) routed by `sgea-<env>-evt-config-compliance` (E3), a failed Security Hub NIST control, a gap in `/sgea/<env>/cloudtrail`, or the scheduled check below. Run that check at least daily. The `-ct-` alarms read the CloudTrail log group, so once the trail has stopped they see nothing more, and if the enclave key is unusable no alarm is delivered at all.

**Likely causes**

- The enclave CMK is disabled or pending deletion. CloudTrail encrypts with it (key-policy Sid `CloudTrail`).
  AWS Config writes to the SSE-KMS store through `ConfigDelivery` (the Config service-linked role) and
  `ConfigServicePrincipal`.
- Someone edited the key policy or a bucket policy. On the log store (Terraform Sids) these are
  `CloudTrailAclCheck` and `CloudTrailWrite`; the CDK `Trail` construct adds equivalent statements. On the Config
  store: `ConfigBucketCheck`, `ConfigDelivery`, `ConfigServiceLinkedRole`.
- The trail was stopped (`StopLogging`), deleted or had its selectors changed. Or the recorder was stopped.
  The SGEA sandbox teardown stops recorder `sgea-<env>`, so that tool must never run outside a sandbox.
- The CloudWatch delivery role `sgea-<env>-cloudtrail-to-cloudwatch` or its policy `sgea-<env>-cloudtrail` changed.
- The landing zone owns AWS Config (`create_config_recorder = false`). The recorder is then not `sgea-<env>`, so
  escalate to the landing-zone owner.

**Triage**

```bash
aws cloudtrail get-trail-status --name sgea-<env> \
    --query '[IsLogging,LatestDeliveryTime,LatestDeliveryError,LatestDigestDeliveryError,LatestCloudWatchLogsDeliveryError]'
aws configservice describe-configuration-recorder-status --configuration-recorder-names sgea-<env>
aws configservice describe-delivery-channel-status --delivery-channel-names sgea-<env>
aws kms describe-key --key-id alias/sgea-<env> --query 'KeyMetadata.[KeyState,DeletionDate]'
aws kms get-key-policy --key-id alias/sgea-<env> --policy-name default --query Policy --output text | jq '.Statement[].Sid'
aws s3api get-bucket-policy --bucket sgea-<env>-logs-<account>-<region> --query Policy --output text | jq '.Statement[].Sid'
# Who changed it (CloudTrail event history, 90 days of management events, independent of the trail):
for e in StopLogging DeleteTrail UpdateTrail PutEventSelectors StopConfigurationRecorder DeleteDeliveryChannel \
         PutKeyPolicy DisableKey ScheduleKeyDeletion PutBucketPolicy; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$e --max-results 5 \
      --query 'Events[].[EventTime,EventName,Username]' --output text
done
```

**Containment.** If the change was not made by your deployment pipeline, treat it as tampering. Run
[playbook 7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt) / [6](#6-guardduty-high-severity-finding)
for the principal that made it, and preserve what is already in the log store.

**Recovery**

1. Recover the key first if needed (`key-and-secret-management.md`).
2. Re-apply the IaC (`terraform apply` / `npx cdk deploy --all`). This restores the trail, the policies and the
   recorder settings.
3. If only stopped: `aws cloudtrail start-logging --name sgea-<env>`;
   `aws configservice start-configuration-recorder --configuration-recorder-name sgea-<env>`.
4. Confirm `LatestDeliveryTime` is moving, then validate the files around the gap:
   `aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:<region>:<account>:trail/sgea-<env> --start-time <gap-start>`.
5. Re-evaluate the pack rules (`aws configservice start-config-rules-evaluation`, or Config console → Conformance
   packs → Re-evaluate).
6. Record the gap. Management events in the gap are still in CloudTrail event history (90 days). Data events in the
   gap are lost.

**Note.** Where the SGEA SCP bundles are deployed, the audit-protection statements (`DenyAuditTampering`, `emitters/policy_library.py`) deny `cloudtrail:StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors`, `config:StopConfigurationRecorder` / `DeleteConfigurationRecorder` / `DeleteDeliveryChannel`, `guardduty:DeleteDetector`, `securityhub:DisableSecurityHub`, `access-analyzer:DeleteAnalyzer`, `logs:DeleteLogGroup` on `/sgea/*` and `kms:ScheduleKeyDeletion` / `DisableKey` / `PutKeyPolicy` on keys tagged `sgea:profile`, for every principal except the CDK bootstrap execution role, `sgea-*-break-glass` and `policies.org_policy_exempt_principal_arns`. A change that got through was made by one of those principals, from the management account (SCPs do not apply there), in an account without the SCPs, or by a role named to match an exemption pattern (the exemption matches role names, ADR 0002). Without the SGEA SCPs, check whether your landing zone's guardrails deny these calls.

**Evidence to keep:** trail and recorder status before and after, the `lookup-events` output, the `validate-logs`
output, the gap window, and the change record of the fix.

**Controls:** AU-5, AU-6, AU-9, AU-12, SI-4, IR-4.

---

## 5. Unexpected object deletion on the log stores

**Trigger.** A message on `sgea-<env>-log-store-events` (`s3:ObjectRemoved:*`) from
`sgea-<env>-logs-<account>-<region>` (log store), `sgea-<env>-config-<account>-<region>` (Config store) or
`sgea-<env>-access-logs-<account>-<region>` (access-log sink). Normal operation deletes nothing:

- Retention is done by lifecycle rules (`retention`: expire at `retention_days`, noncurrent versions after 30
  days). S3 reports lifecycle expirations as lifecycle events, not `ObjectRemoved`.
- The only SGEA tool that deletes objects is the sandbox teardown.

**Likely causes:** manual cleanup by an operator, tampering to cover activity, a tenant or tool role with
`s3:DeleteObject` on `sgea-<env>-*`, or an Object Lock bypass.

**Triage**

1. Read the SNS message: `eventName` (`ObjectRemoved:Delete` or `ObjectRemoved:DeleteMarkerCreated`), bucket, key,
   `versionId`, `userIdentity.principalId`, `requestParameters.sourceIPAddress`.
2. Find who did it:
   - **Log store.** The trail excludes the log store's own objects from S3 data events (to keep the trail's own
     deliveries out). Use the S3 server access logs in `sgea-<env>-access-logs-<account>-<region>` under the prefix
     `sgea-<env>-logs-<account>-<region>/`. Look for `REST.DELETE.OBJECT` and `BATCH.DELETE.OBJECT`, and the
     requester and `x-amz-bypass-governance-retention`. Access-log delivery can be delayed.
   - **Config store and access-log sink.** Where the profile logs S3 data events (`s3-enclave-buckets`), CloudTrail
     data events are in the log store and in `/sgea/<env>/cloudtrail`. Logs Insights:
     `filter eventName in ["DeleteObject","DeleteObjects"] and requestParameters.bucketName like /sgea-<env>-/`.
3. Check what is left:
   ```bash
   aws s3api list-object-versions --bucket <bucket> --prefix <key>
   aws s3api get-object-retention --bucket <bucket> --key <key> --version-id <version>   # Object Lock stores
   aws s3api head-object --bucket sgea-<env>-logs-replica-<account>-<replica-region> --key <key> --region <replica-region>
   ```
   A delete marker means the data is still there. Delete markers are not replicated (`delete_marker_replication`
   off), so the replica keeps the object.

**Containment** (needs approval, because it changes production policy): disable or revoke the principal (playbooks 6
and 7). If deletions continue, add a temporary explicit `Deny s3:DeleteObject*` on the affected bucket. Record it as
drift and remove it by re-applying the IaC once contained. Put legal holds on critical objects if counsel asks
(`aws s3api put-object-legal-hold`).

**Recovery**

1. **Delete marker:** remove the marker (`aws s3api delete-object --bucket <b> --key <k> --version-id <marker-id>`)
   before the 30-day noncurrent expiry.
2. **Version permanently deleted:** copy it back from the replica bucket, or restore the store from the AWS Backup
   vault `sgea-<env>`. The log and Config stores are in the `sgea-<env>-enclave` selection.
3. For CloudTrail files, re-run `aws cloudtrail validate-logs` over the affected window and record the result.

**Evidence to keep:** the SNS messages, access-log or CloudTrail lines that name the requester, version listings,
`validate-logs` output, and restore job ids.

**Controls:** AU-9, AU-11, AU-6, SI-4, IR-4, IR-5.

---

## 6. GuardDuty high-severity finding

**Trigger.** A GuardDuty finding with severity 7 or higher in the enclave account and region, delivered to `sgea-<env>-security-alarms` by `sgea-<env>-evt-guardduty` (E1, the raw finding event). GuardDuty also imports findings into Security Hub, so the same finding can arrive a second time through `sgea-<env>-evt-securityhub`. Medium and low findings are not routed; your SIEM or landing zone covers them. The `guardduty-non-archived-findings` pack rule turns non-compliant on findings left open too long. In the FedRAMP Moderate pack the limits are 1 day for high, 7 for medium and 30 for low (pack parameters).

**Triage**

```bash
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id "$DET" \
    --finding-criteria '{"Criterion":{"severity":{"Gte":7},"service.archived":{"Eq":["false"]}}}'
aws guardduty get-findings --detector-id "$DET" --finding-ids <id> > finding-<id>.json
```

Map the affected resource to the enclave. IAM roles are named `sgea-<env>-*` (for example
`sgea-<env>-agentcore-gateway`, `sgea-<env>-agentcore-memory`), buckets `sgea-<env>-*`, functions
`sgea-<env>-tool-policy` / `sgea-<env>-token-meter`; tenant roles are the tenant's. Then pivot in CloudTrail on the
access key id or session name. Network findings: `/sgea/<env>/vpc-flow-logs` (or the VDMS flow logs on DoD SCCA
profiles).

**Containment by resource type**

| Resource | Action | Side effect to record |
|---|---|---|
| IAM role credentials | IAM console → role → *Revoke active sessions* | Adds the inline policy `AWSRevokeOlderSessions`. The enclave forbids inline policies (`iam-no-inline-policy-check`), so Config reports NON_COMPLIANT. Record it as an incident exception and remove the policy after rotation |
| Enclave or tenant Lambda | `aws lambda put-function-concurrency --function-name <fn> --reserved-concurrent-executions 0` | On `sgea-<env>-tool-policy` every tool call then fails. `lambda-concurrency-check` goes non-compliant |
| S3 data access | [Playbook 5](#5-unexpected-object-deletion-on-the-log-stores) | — |
| Network (ENI in the enclave VPC) | Move the ENI to a deny-all security group | Breaks that workload |

**Recovery.** Rotate the affected credentials. Re-apply the IaC to remove containment drift. Then archive the finding
with the ticket reference: `aws guardduty archive-findings --detector-id "$DET" --finding-ids <id>`.

**Evidence to keep:** the finding JSON, CloudTrail for the principal, flow-log extracts, containment and rotation
records.

**Controls:** SI-4, IR-4, IR-5, IR-6, AU-6.

---

## 7. Suspected credential compromise of a tenant user (Cognito / JWT)

**Context.** Tenant runtimes and (when a JWT issuer is set) the gateway use a custom JWT authorizer: the OIDC
`discovery_url` plus `allowed_clients`; the Terraform runtime wrapper also takes `allowed_audience`. The enclave does not own the IdP. The
sample tenant's Cognito user pool is a **test** IdP (`<name>-test-idp`, public client with no secret, 60-minute
access and ID tokens, MFA optional). The authorizer checks the signature and expiry, so **an access token that has
already been issued stays valid until it expires**. Containment has to cover that window.

**Trigger:** a user report, an IdP risk alert, a GuardDuty finding, the anomalies in playbooks 1 and 2, or an
unexpected `client_id` in the interceptor log.

**Triage**

1. Activity by the identity's `sub` in the interceptor log:
   `aws logs filter-log-events --log-group-name /aws/lambda/sgea-<env>-tool-policy --filter-pattern '{ $.user = "<sub>" }'`.
2. Model usage by that identity: the Logs Insights query in playbook 2, step 4.
3. Runtime calls: AgentCore data events (`eventSource` `bedrock-agentcore.amazonaws.com`) in
   `/sgea/<env>/cloudtrail`.
4. IdP sign-in history. Cognito:
   `aws cognito-idp admin-list-user-auth-events --user-pool-id <pool> --username <user>`.

**Containment**

1. Disable the identity at the IdP. Cognito: `aws cognito-idp admin-disable-user` and
   `aws cognito-idp admin-user-global-sign-out --user-pool-id <pool> --username <user>`. Global sign-out revokes
   refresh tokens; access tokens already issued keep working until they expire.
2. Cover the token lifetime:
   - **Interceptor tool-path mode:** add `{"effect":"deny","tools":["*"],"claim":"sub","values":["<sub>"]}` to
     `tool_policy` and redeploy. Deny overrides allow.
   - **Policy-engine mode:** add a forbid policy for the caller to `sgea_<env>_tool_policy` (check the principal
     format against the AgentCore Policy documentation).
3. If the whole client or the IdP signing keys are compromised: remove the client id from `jwt_allowed_clients` /
   `agent_jwt_allowed_clients` (CDK `sgea:jwtAllowedClients`) and redeploy. This blocks every user of that client.
   Rotate the signing keys with the IdP's own procedure.
4. **Workload role compromise (gateway AWS_IAM auth).** The interceptor trusts the `X-Sgea-User` / `X-Sgea-Team`
   headers from the IAM-authenticated workload. A stolen role credential can act as any user for budgets and tool
   policy. Revoke the role's sessions ([playbook 6](#6-guardduty-high-severity-finding)).

**Recovery.** Reset the user's credentials and enforce MFA at the production IdP. Remove temporary deny rules once
the token lifetime has passed. Re-enable the user after the incident lead confirms.

**Evidence to keep:** IdP auth events, interceptor lines, invocation-log query results (counts, not text), CloudTrail
extracts, and the containment change records.

**Controls:** AC-2, IA-2, IA-5, IR-4, IR-6, AU-6.

---

## 8. Audit-trail or security-configuration tampering

**Trigger.** One of these alarms (C1), each raised by a single matching CloudTrail event in 5 minutes:

| Alarm | Events |
|---|---|
| `sgea-<env>-ct-cloudtrail-changes` | `CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging`, `PutEventSelectors` |
| `sgea-<env>-ct-config-changes` | AWS Config `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `PutConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel` |
| `sgea-<env>-ct-kms-key-disable-or-delete` | `DisableKey`, `ScheduleKeyDeletion` on any KMS key |
| `sgea-<env>-ct-iam-policy-changes` | IAM `Put*Policy`, `Delete*Policy`, `Create*Policy*`, `Attach*Policy`, `Detach*Policy` |
| `sgea-<env>-ct-s3-bucket-policy-changes` | Bucket ACL, policy, CORS, lifecycle or replication put or deleted |
| `sgea-<env>-ct-organizations-changes` | AWS Organizations policy, account or membership change (most events are recorded in the management account; a member account records for example `LeaveOrganization`) |

Every IaC apply that touches IAM or bucket settings raises some of these, and so do tenant deploys (`-ct-iam-policy-changes`). Check the change calendar first.

**Likely causes**

- An approved apply of the enclave, a tenant app or the landing zone.
- A console or CLI change outside the IaC (drift).
- Tampering to hide activity: stopping the trail or recorder, opening a bucket, removing replication or lifecycle protection, or disabling or scheduling deletion of the enclave key.

**Triage**

1. Find the events with the alarm's filter pattern (the command under the signal inventory). Record `eventTime`, `eventName`, `userIdentity.arn`, `sourceIPAddress` and `requestParameters`.
2. Was the principal a deployment principal (CDK `cdk-hnb659fds-cfn-exec-role-*`, your Terraform pipeline role, the landing-zone pipeline) inside an approved change window? A human role or an unknown principal is a finding.
3. Does the change touch an enclave resource? Trail and recorder `sgea-<env>`, buckets `sgea-<env>-*`, roles and policies `sgea-<env>-*`, the key `alias/sgea-<env>` (`aws kms describe-key --key-id alias/sgea-<env> --query KeyMetadata.KeyId` against `requestParameters.keyId`).
4. Compare the account with the code: `terraform plan` (read-only) or CloudFormation drift detection (`aws cloudformation detect-stack-drift --stack-name SgeaEnclave`, then `describe-stack-resource-drifts`).
5. Where the audit-protection SCP is deployed, a denied attempt shows as `-ct-unauthorized-api` with `errorCode` `AccessDenied` and no change. The control worked, but who tried still matters ([playbook 10](#10-root-use-console-sign-in-without-mfa-failed-sign-ins-unauthorized-api-calls)). A tampering call that succeeded despite the SCP came from an exempt principal (see the note in [playbook 4](#4-cloudtrail-or-aws-config-delivery-stopped)); for a role whose name matches `sgea-*-break-glass` or `cdk-hnb659fds-cfn-exec-role-*`, check when and by whom it was created (`CreateRole` in CloudTrail).

**Containment** (needs approval). Not made by an approved pipeline or change: treat it as tampering. Revoke the principal's sessions ([playbook 6](#6-guardduty-high-severity-finding)) or disable the identity ([playbook 7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt)). Trail or recorder affected: [playbook 4](#4-cloudtrail-or-aws-config-delivery-stopped). Enclave key scheduled for deletion: cancel it now ([key and secret management](key-and-secret-management.md), section 2). Bucket opened or replication removed: re-apply the IaC, or add a temporary explicit deny as in [playbook 5](#5-unexpected-object-deletion-on-the-log-stores).

**Recovery.** Re-apply the IaC so the account matches its code and its AWS Config evidence. Where the trail was touched, run `aws cloudtrail validate-logs` over the window and record any gap. Remove leftover IAM policies or attachments that no change record explains.

**Evidence to keep:** the alarm history, the CloudTrail events, the plan or drift output before and after, and the change record (or the incident record if there was none).

**Controls:** AU-6, AU-9, CM-3, CM-5, AC-6, SI-4, IR-4.

---

## 9. Network configuration change

**Trigger.** One of `sgea-<env>-ct-security-group-changes` (security group created, deleted, or ingress / egress rules authorized or revoked), `-ct-nacl-changes` (network ACL or entry created, deleted, replaced or re-associated), `-ct-network-gateway-changes` (internet or customer gateway created, attached, detached or deleted), `-ct-route-table-changes` (route or route table created, replaced, deleted or disassociated) or `-ct-vpc-changes` (VPC created, deleted or modified, peering connections, ClassicLink). They cover the whole account and every region the trail records, not only the enclave VPC.

**Likely causes:** the enclave or a tenant deploy (interface endpoints, runtime and function security groups), the landing-zone network pipeline (the VPC and subnets are customer-owned), a manual change, or an attempt to open a path out of the enclave (an internet gateway or a `0.0.0.0/0` route on the agent subnets, a peering connection, an open ingress rule).

**Triage**

1. Find the events with the alarm's filter pattern (command under the signal inventory). Note the VPC, security group, route table or gateway id and the principal.
2. Is the resource in the enclave VPC (the `vpc_id` input / CDK `sgea:vpcId`)? Changes elsewhere go to the owner of that network.
3. For a security group: does a new rule allow `0.0.0.0/0` or `::/0`, or a port other than 443 to the endpoints? For a route: does it send the agent subnets to an internet gateway, NAT gateway or peering connection? For peering: which account?
4. Look for traffic through the new path in `/sgea/<env>/vpc-flow-logs` (or the VDMS flow logs on DoD SCCA profiles). The conformance-pack network rules (for example `vpc-sg-open-only-to-authorized-ports`, `restricted-ssh`) report through `sgea-<env>-evt-config-compliance` as well.

**Containment** (needs approval). Revert the change: revoke the rule, delete the route, detach the gateway or reject the peering. If the principal is not expected, revoke its sessions ([playbook 6](#6-guardduty-high-severity-finding)). If traffic left the enclave, treat it as a data incident and engage privacy / legal where PII or PHI may be involved.

**Recovery.** Re-apply the enclave IaC (endpoints, security groups, flow logs) and ask the network owner to re-apply theirs. Record the window during which the path was open.

**Evidence to keep:** the CloudTrail events, flow-log extracts for the window, the revert change record.

**Controls:** SC-7, AC-4, CM-3, CM-5, SI-4, IR-4.

---

## 10. Root use, console sign-in without MFA, failed sign-ins, unauthorized API calls

**Trigger.** One of:

| Alarm | Fires on |
|---|---|
| `sgea-<env>-ct-root-usage` | Any root-user call that is not made by an AWS service on its behalf |
| `sgea-<env>-ct-console-no-mfa` | A successful console sign-in by an IAM user without MFA |
| `sgea-<env>-ct-console-auth-failures` | A failed console sign-in |
| `sgea-<env>-ct-unauthorized-api` | Any call that failed with `*UnauthorizedOperation` or `AccessDenied*` |

`-ct-unauthorized-api` is the noisiest alarm in the layer: a deny from an SCP, a permissions boundary, a missing `kms:Decrypt` or a tool that probes with `Describe*` calls all count.

**Likely causes:** a planned root task (closing the account, changing the support plan, some billing settings); an IAM user the landing zone or a team created (the enclave creates no IAM users); password guessing; a misconfigured role after a deploy; the audit-protection or other SGEA SCPs working; enumeration with stolen credentials.

**Triage**

1. Find the events with the alarm's filter pattern (command under the signal inventory).
2. Root: is there an approved root task? Check `aws iam get-account-summary --query 'SummaryMap.[AccountMFAEnabled,AccountAccessKeysPresent]'` (expected `1` and `0`).
3. Console without MFA: which IAM user, from where? Its owner, and why it has a console password.
4. Failed sign-ins: count by user name and source IP; many users from one IP, or many attempts for one user, is guessing.
5. Unauthorized calls: group them in Logs Insights on `/sgea/<env>/cloudtrail`:
   ```
   filter errorCode like /UnauthorizedOperation/ or errorCode like /^AccessDenied/
   | stats count() as denies by userIdentity.arn, eventSource, eventName, errorMessage
   | sort denies desc
   ```
   One enclave or tenant role failing the same call after a deploy is a misconfiguration: fix it through the IaC. One principal failing many different calls across services is enumeration: go to [playbook 6](#6-guardduty-high-severity-finding) and [playbook 7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt). A deny whose message names a service control policy is an SCP working as designed; record who tried.

**Containment** (needs approval). Root not approved: secure the root user now (reset the password, check the MFA devices, delete any root access key) and treat it as an account compromise. IAM user without MFA: remove the console password (`aws iam delete-login-profile --user-name <user>`) or require MFA, and deactivate keys the owner cannot explain. Guessing: block the source at your IdP or network edge. Enumeration: revoke the principal's sessions.

**Recovery.** Rotate the credentials involved. Prefer IAM Identity Center or federation over IAM users. Record root use with its approval. If `-ct-unauthorized-api` fires every day for the same known cause, fix the cause rather than ignoring the alarm.

**Evidence to keep:** the CloudTrail events, the Logs Insights result, root or IAM-user records and approvals, rotation records.

**Controls:** AC-2, AC-6(9), AC-7, IA-2(1), AU-6, SI-4, IR-4.

---

## 11. Break-glass role assumed

**Trigger.** Alarm `sgea-<env>-ct-break-glass-assumed` (C4): an `AssumeRole` call on `sgea-<env>-break-glass`. The role exists only with `create_break_glass_role` (CDK `sgea:createBreakGlassRole`) and `break_glass_principal_arns` (CDK `sgea:breakGlassPrincipalArns`). It requires MFA within the last hour, sessions last at most one hour, and it has `AdministratorAccess`. Every assumption raises the alarm: expected during a declared emergency, an incident otherwise.

**Triage**

1. Is there an open incident or emergency change that declared break-glass use? Contact the person who holds it.
2. Find the assumption with the alarm's filter pattern (command under the signal inventory): the calling principal (`userIdentity.arn`), `sourceIPAddress`, and the session (`responseElements.assumedRoleUser.arn`).
3. List what the session did. Logs Insights on `/sgea/<env>/cloudtrail`:
   ```
   filter userIdentity.arn like /assumed-role\/sgea-<env>-break-glass\//
   | stats count() as calls by eventSource, eventName
   | sort calls desc
   ```
4. The role is exempt from the audit-protection SCP. Check whether other `-ct-` alarms fired in the same window ([playbook 8](#8-audit-trail-or-security-configuration-tampering)).

**Containment** (not authorized). Revoke the role's sessions (IAM console → role → *Revoke active sessions*; this adds the inline policy `AWSRevokeOlderSessions`, recorded as in [playbook 6](#6-guardduty-high-severity-finding)). Disable the source identity at the IdP or in IAM and treat it as a credential compromise. Remove the principal from `break_glass_principal_arns` and redeploy, or set `create_break_glass_role` to false. Act fast: the session lasts up to one hour.

**Recovery.** Post-use review within one business day ([access review](access-review.md), section 6): who, why, every action from step 3, drift reconciled (`terraform plan` or CloudFormation drift detection), credentials rotated, ISSO sign-off.

**Evidence to keep:** the alarm, the `AssumeRole` event, the session's activity, the approval (or the incident record), the post-use review.

**Controls:** AC-2, AC-6, AU-6, CM-3, IR-4.

---

## 12. Security Hub, Inspector or Access Analyzer finding

**Trigger.** One of these events on `sgea-<env>-security-alarms` (E2):

- `sgea-<env>-evt-securityhub`: a new (workflow status NEW) HIGH or CRITICAL finding imported into Security Hub, from any integrated product. GuardDuty findings arrive here too ([playbook 6](#6-guardduty-high-severity-finding)).
- `sgea-<env>-evt-inspector`: a HIGH or CRITICAL Amazon Inspector finding, for example a vulnerable package in an image in `sgea-<env>-agents` or in a Lambda function.
- `sgea-<env>-evt-access-analyzer`: an ACTIVE finding of the IAM Access Analyzer `sgea-<env>-external-access` (zone of trust: this account): a resource policy that grants access to a principal outside the account. Unused-access findings from `sgea-<env>-unused-access` (if turned on) are reviewed in the quarterly [access review](access-review.md).

**Triage**

```bash
# Security Hub: the id is in detail.findings[].Id of the event
aws securityhub get-findings --filters '{"Id":[{"Value":"<finding-id>","Comparison":"EQUALS"}]}' \
    --query 'Findings[].[ProductName,Title,Severity.Label,Resources[].Id]'
# Inspector: the ARN is in detail.findingArn
aws inspector2 list-findings --filter-criteria '{"findingArn":[{"comparison":"EQUALS","value":"<finding-arn>"}]}'
# Access Analyzer: the id is in detail.id
aws accessanalyzer get-finding --id <finding-id> \
    --analyzer-arn arn:aws:access-analyzer:<region>:<account>:analyzer/sgea-<env>-external-access
```

Map the resource to its owner: `sgea-<env>-*` is the enclave, tenant resources belong to the tenant. For Access Analyzer, compare the policy with the expected resource policies in the [access review](access-review.md), section 5; access that no record explains is a finding.

**Containment.** Exposed resource (Access Analyzer, or a Security Hub control on public access): remove the statement now (approval), then fix the source. Exploitable vulnerability in a running image or function: stop or isolate the workload ([playbook 6](#6-guardduty-high-severity-finding), table) until it is rebuilt.

**Recovery.** Fix through the IaC or the tenant's pipeline (rebuild the image, upgrade the runtime or the SGEA toolkit). Then close the finding with the ticket reference: Security Hub `aws securityhub batch-update-findings` (workflow `RESOLVED`, or `SUPPRESSED` for an accepted risk with ISSO approval), Inspector suppression rule for accepted risk, Access Analyzer `aws accessanalyzer update-findings --status ARCHIVED` or an archive rule for intended access.

**Evidence to keep:** the finding JSON, the fix change record, the risk acceptance for suppressed or archived findings.

**Controls:** RA-5, SI-2, SI-4, AC-3, AC-6, CA-7, IR-4.

---

## 13. AWS Config rule non-compliant or stack drift

**Trigger.** One of these events (E3):

- `sgea-<env>-evt-config-compliance`: any AWS Config rule in the account and region, including the conformance-pack rules and the landing zone's rules, turned NON_COMPLIANT for a resource.
- `sgea-<env>-evt-stack-drift` (CDK only): CloudFormation drift detection found an SGEA stack DRIFTED. The EventBridge Scheduler schedule `sgea-<env>-drift-detect` runs drift detection daily on the SGEA stacks in the primary region (not on the log-replica stack), as role `sgea-<env>-drift-scheduler` (the two drift actions on the SGEA stacks plus the AWS managed `ReadOnlyAccess`). Terraform has no drift event: a scheduled `terraform plan -detailed-exitcode` in your pipeline exits 2 on drift; treat that result the same way.

**Triage**

1. Config: read `detail.configRuleName`, `detail.resourceType`, `detail.resourceId` and `detail.newEvaluationResult.annotation`. Then
   `aws configservice get-compliance-details-by-config-rule --config-rule-name <rule> --compliance-types NON_COMPLIANT`.
2. Is it expected? Known findings in `MANUAL-STEPS.md` (for example SGEA-KF-02), a recorded exception, a containment change from another playbook (an `AWSRevokeOlderSessions` inline policy, zero Lambda concurrency), or a transient result during a deploy. `docs/CONTROL-COVERAGE.md` shows how SGEA handles the rule.
3. Drift: `aws cloudformation describe-stack-resource-drifts --stack-name SgeaEnclave --stack-resource-drift-status-filters MODIFIED DELETED` lists what changed and how.
4. A rule or drift on the trail, the recorder, the key, IAM or the network: also run [playbook 8](#8-audit-trail-or-security-configuration-tampering) or [9](#9-network-configuration-change).

**Containment.** Usually none. If the change opened access or stopped logging, follow the matching playbook.

**Recovery.** Re-apply the IaC after reviewing the plan or change set; this reconciles drift. If the change should stay, bring it into the profile or inputs ([change and upgrade](change-and-upgrade.md)) instead. Re-evaluate the rule (`aws configservice start-config-rules-evaluation --config-rule-names <rule>`) and confirm it is compliant.

**Evidence to keep:** the event, the compliance details or drift output, and the change record that fixed or accepted it.

**Controls:** CM-2, CM-3, CM-6, CA-7, SI-4.

---

## 14. Backup job or secret rotation failed

**Trigger.** One of these events (E4):

- `sgea-<env>-evt-backup`: an AWS Backup backup, copy or restore job in the account and region ended FAILED, ABORTED or EXPIRED (EXPIRED: the job did not start within its window). Jobs of other backup plans in the account match too.
- `sgea-<env>-evt-secret-rotation`: Secrets Manager reported `RotationFailed`, for example for the RDS-managed Aurora admin secret of `sgea-<env>-vector`.

**Triage**

```bash
aws backup describe-backup-job --backup-job-id <id> --query '[State,StatusMessage,ResourceArn,BackupVaultName]'
aws backup list-backup-jobs --by-backup-vault-name sgea-<env> --by-state FAILED --max-results 20
aws secretsmanager describe-secret --secret-id <secret-arn> --query '[RotationEnabled,LastRotatedDate,NextRotationDate]'
aws rds describe-db-clusters --db-cluster-identifier sgea-<env>-vector --query 'DBClusters[0].MasterUserSecret.SecretStatus'
```

Common causes: the enclave key disabled or its grants missing; the resource deleted or stopped; a change to the role `sgea-<env>-backup`; the vault lock minimum retention conflicting with a changed lifecycle; for rotation, the secret status `impaired` (RDS cannot use the key or the secret).

**Containment.** None needed: the previous recovery point and the current credential stay valid. Record the window without a fresh recovery point (RPO) or without rotation.

**Recovery.** Fix the cause, then take an on-demand backup (`aws backup start-backup-job --backup-vault-name sgea-<env> --resource-arn <arn> --iam-role-arn <arn of sgea-<env>-backup>`) or retry the rotation (`aws secretsmanager rotate-secret --secret-id <secret-arn>`). A failed restore job usually belongs to a restore test (`OPERATIONS.md`): repeat the test after the fix.

**Evidence to keep:** the job or rotation events, the fix, the new recovery point or rotation date, and the RPO gap.

**Controls:** CP-9, CP-10, IA-5, SI-4.

---

## 15. Bedrock or gateway service health

**Trigger.** One of the health alarms (H1, H3):

| Alarm | Means | First look |
|---|---|---|
| `sgea-<env>-bedrock-throttles` | At least 10 throttled model calls in each of two 5-minute periods (account total) | Service quotas (tokens and requests per minute per model), a runaway agent ([playbook 2](#2-token-budget-exhausted-for-a-user-or-team), step 4 query) |
| `sgea-<env>-bedrock-server-errors` | At least 5 Bedrock server errors in 5 minutes | AWS Health Dashboard for Amazon Bedrock in the region; the model in use |
| `sgea-<env>-bedrock-invocation-log-delivery` | Model-invocation logs not delivered to CloudWatch for 15 minutes | Logging configuration, role `sgea-<env>-bedrock-invocation-logging`, log group `/sgea/<env>/bedrock/model-invocations`, enclave key |
| `sgea-<env>-gateway-system-errors` | At least 5 gateway system errors on MCP `InvokeGateway` in 5 minutes | Gateway targets (tenant tool functions), the interceptor (alarm A1, log L1) |
| `sgea-<env>-gateway-throttles` | At least 10 gateway throttles in each of two 5-minute periods | AgentCore quotas, caller retry behavior |

**Triage**

```bash
aws cloudwatch describe-alarm-history --alarm-name sgea-<env>-<alarm> --history-item-type StateUpdate --max-items 5
aws service-quotas list-service-quotas --service-code bedrock \
    --query 'Quotas[?contains(QuotaName, `tokens per minute`)].[QuotaName,Value]' --output table
aws bedrock get-model-invocation-logging-configuration
```

For throttles, find the models and apps involved (Bedrock metrics by `ModelId`; the invocation-log query in [playbook 2](#2-token-budget-exhausted-for-a-user-or-team), step 4). For log delivery, check that the logging configuration still names the role and log group, that the role's policy is unchanged and that the key is `Enabled`.

**Impact.** Throttles and server errors fail tenant requests. Missing invocation logs are an audit gap and stop the token meter from crediting usage, so budgets under-count while it lasts (the meter heartbeat keeps running, so the interceptor does not fail closed). Gateway errors fail tool calls.

**Containment.** Throttles: slow down or stop the offending app or agent (tenant team), or lower its token budget. Server errors: tenant apps retry with backoff; nothing changes in the enclave. Log delivery: re-apply the IaC to restore the logging configuration.

**Recovery.** Request a quota increase where the load is legitimate. Record the window of missing invocation logs (counts in the S3 copy under `s3://sgea-<env>-logs-<account>-<region>/bedrock/` may still be complete) and the under-credited token usage.

**Evidence to keep:** alarm history, quota values, the logging configuration before and after, the gap window.

**Controls:** SC-5, AU-5, AU-12, SI-4, IR-4.

---

## 16. Budget or cost anomaly alert

**Trigger.** A notification from AWS Budgets on `sgea-<env>-monthly-cost`: actual cost over 80 % or forecast cost over 100 % of `monthly_budget_usd` (CDK `sgea:monthlyBudgetUsd`). Or an AWS Cost Anomaly Detection alert from `sgea-<env>-anomalies`: an anomaly with a total impact of at least USD 100 on the per-service monitor `sgea-<env>-services` (opt-in `create_cost_anomaly_monitor` / `sgea:createCostAnomalyMonitor`, because an account allows only one per-service monitor and AWS often creates a default one). Both cover the whole account, not only the enclave, and exist only in the commercial partition.

**Likely causes:** heavy model use by a tenant, an agent in a loop, a new tenant or a larger model, resources left behind in a test, or abuse of stolen credentials (for example compute in an unused region).

**Triage**

```bash
aws ce get-cost-and-usage --time-period Start=<YYYY-MM-01>,End=<YYYY-MM-DD> --granularity DAILY \
    --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE
aws ce get-anomalies --date-interval StartDate=<YYYY-MM-DD>,EndDate=<YYYY-MM-DD> \
    --query 'Anomalies[].[AnomalyStartDate,Impact.TotalImpact,RootCauses]'
```

Bedrock cost: find who used the tokens ([playbook 2](#2-token-budget-exhausted-for-a-user-or-team), step 4 query). Cost in a region outside the profile or a service the enclave does not use: check GuardDuty ([playbook 6](#6-guardduty-high-severity-finding)) and treat it as a possible credential compromise. If you activated `sgea:tenant` or `sgea:profile` as cost allocation tags, group by them.

**Containment.** Budgets and anomaly alerts stop nothing. Have the tenant team stop a runaway app; lower token budgets through the profile; for abuse, revoke the credentials and remove the resources.

**Recovery.** Adjust `monthly_budget_usd` through the IaC when the new level is approved. Record the cause.

**Evidence to keep:** the alert, the cost breakdown, the cause and any budget change approval.

**Controls:** SC-6, SI-4, IR-4.

---

## Contacts and escalation (fill in)

| Role | Name / team | Primary contact | Backup | When to engage |
|---|---|---|---|---|
| Incident lead (on call) | | | | Every playbook |
| ISSO / security officer | | | | Guardrail or budget changes, risk acceptance, break-glass use (playbook 11), every confirmed incident |
| Enclave platform owner (IaC) | | | | Redeploys, containment drift, playbooks 13–15 |
| Landing-zone / Config / GuardDuty owner | | | | Playbooks 4, 6, 8, 9, 12 and 13 when the landing zone owns the service or the network |
| IdP owner | | | | Playbook 7 |
| Tenant app owner | | | | Playbooks 1, 2, 7, 12, 15, 16 |
| Cost owner (FinOps) | | | | Playbook 16 |
| Privacy / legal (PII, PHI) | | | | Possible PII or PHI exposure, legal hold |
| AWS Support | Case in the enclave account | | | Service-side faults |
| External reporting (authorizing official, agency, covered entity) | | | | As required by your SSP / authorization (IR-6) |

## Post-incident review checklist

- [ ] Timeline built from CloudTrail (`validate-logs` passed for the window), the interceptor and meter logs, and
      alarm history.
- [ ] Root cause recorded. Was it a control working as designed (fail-closed, guardrail) or a failure?
- [ ] Every containment change (deny statements, revoked sessions, zero concurrency) removed or kept as a recorded
      exception. IaC re-applied. `sgea check` and the conformance packs compliant again.
- [ ] Gaps recorded: audit-log gap window, under-credited token usage, deleted or restored objects.
- [ ] Profile changes (guardrail, budgets, tool policy) approved by the ISSO and committed with the export.
- [ ] Alerting reviewed: did a signal in the inventory fire, and early enough? Thresholds or toggles changed through the IaC where it was noisy or silent; topic subscriptions current.
- [ ] Reporting obligations met and recorded (IR-6); privacy / legal informed where PII or PHI was involved.
- [ ] Evidence filed with the incident record. Prompt text only where the incident lead requires it.
- [ ] Playbook and contacts table updated; lessons fed into the next incident-response exercise.
