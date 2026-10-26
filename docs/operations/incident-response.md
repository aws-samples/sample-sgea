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
| S1 | SNS `sgea-<env>-log-store-events`: `s3:ObjectRemoved:*` from the log store, the AWS Config store and the access-log sink (primary region; the replica buckets do not notify) | `enclave-logging` / `hardened-bucket` | subscribers you add | [5](#5-unexpected-object-deletion-on-the-log-stores) |
| L1 | Interceptor decision log: one JSON line per `tools/call` (`sgea`, `decision`, `reason`, `tool`, `user`, `team`, `client_id`; never the token) | `emitters/lambda/tool_policy_interceptor.py` | `/aws/lambda/sgea-<env>-tool-policy` | [2](#2-token-budget-exhausted-for-a-user), [3](#3-gateway-interceptor-denies-every-tool-call), [7](#7-suspected-credential-compromise-of-a-tenant-user-cognito--jwt) |
| L2 | Guardrail interventions: the caller sees `Blocked by enclave guardrail.` | `bedrock-guardrail` (`blocked_input_messaging` / `blocked_outputs_messaging`) | model-invocation logs | [1](#1-guardrail--pii-block-spike) |
| L3 | CloudTrail `sgea-<env>` (multi-region, log-file validation, enclave CMK; Bedrock / AgentCore / S3 data events per profile) and AWS Config recorder / delivery channel `sgea-<env>` | `enclave-logging`, `config-conformance` | log store, `/sgea/<env>/cloudtrail`, Config store | [4](#4-cloudtrail-or-aws-config-delivery-stopped) |
| G1 | GuardDuty detector (`FIFTEEN_MINUTES` publishing) and Security Hub with NIST SP 800-53 Rev 5 | `security-services` (unless `create_guardduty` / `create_securityhub` = false) | GuardDuty / Security Hub consoles, your SIEM | [6](#6-guardduty-high-severity-finding) |

What the IaC does **not** do, so plan for it:

- It creates **no subscriptions** on `sgea-<env>-security-alarms` or `sgea-<env>-log-store-events`. Subscribing the
  security team is a post-deploy step (`MANUAL-STEPS.md`). Both topics are encrypted with the enclave CMK. An SQS or
  Lambda subscriber needs `kms:Decrypt` on that key.
- It creates **no alarm** for guardrail interventions, CloudTrail or AWS Config delivery, or GuardDuty findings
  (L2, L3, G1). Those playbooks start from a scheduled check, a Config rule result or your SIEM. To route
  EventBridge events to `sgea-<env>-security-alarms`, you need a topic policy statement for `events.amazonaws.com`
  and a matching statement in the enclave key policy. Today the key policy has neither.
- Alarm INSUFFICIENT_DATA actions are present only when the composed packs require them
  (`alarm_insufficient_data_action`, from the pack parameters of `cloudwatch-alarm-action-check`).

Check that the alarms exist and see their state:

```bash
aws cloudwatch describe-alarms --alarm-names sgea-<env>-tool-policy-errors sgea-<env>-token-meter-errors \
    sgea-<env>-token-meter-silent --query 'MetricAlarms[].[AlarmName,StateValue,StateUpdatedTimestamp]' --output table
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:<region>:<account>:sgea-<env>-security-alarms
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:<region>:<account>:sgea-<env>-log-store-events
```

(GovCloud: partition `aws-us-gov` in every ARN.)

---

## 1. Guardrail / PII block spike

**Trigger.** Users or a tenant team report many `Blocked by enclave guardrail.` answers, or your own query on the
invocation logs (step 2) shows more blocks than usual. SGEA does not alarm on this.

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

## 2. Token budget exhausted for a user

**Trigger.** A tool call returns JSON-RPC error `-32003` with
`Tool call denied by enclave token-budget: per-user daily token budget exhausted` (or
`per-team monthly token budget exhausted`). This is the control working, so there is no alarm. Budgets gate
**gateway tool calls** (`tools/call`). The interceptor does not block model invocations.

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

**Containment:** if the usage is not the user's, go to playbook 7. For a runaway agent, have the tenant team stop the
session or app.

**Recovery**

- The user budget resets at the next day in `TOKEN_TIMEZONE`. The team budget resets at the next month.
- To raise a budget, change `token_control.per_user_daily_tokens` / `per_team_monthly_tokens` in the profile,
  re-export and redeploy. The interceptor reads its budgets from its environment.
- Do not edit or delete ledger items. They are the usage record (PITR on, covered by the backup plan).

**Evidence to keep:** the deny log lines, the ledger item, the per-user token query, and the approval for any
budget change.

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

**Trigger.** SGEA has no alarm for this. It shows up as a non-compliant conformance-pack rule
(`cloudtrail-enabled`, `multi-region-cloudtrail-enabled`, `cloud-trail-cloud-watch-logs-enabled`,
`cloud-trail-log-file-validation-enabled`), a failed Security Hub NIST control, a gap in `/sgea/<env>/cloudtrail`,
or the scheduled check below. Run that check at least daily.

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

**Note.** The SGEA SCP library (`emitters/policy_library.py`) has no statement that denies `cloudtrail:StopLogging`,
`config:StopConfigurationRecorder` or `kms:ScheduleKeyDeletion`. Check whether your landing zone's guardrails do.

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

**Trigger.** A GuardDuty finding with severity 7 or higher in the enclave account and region. SGEA enables the
detector and Security Hub (NIST SP 800-53 Rev 5) but **does not route findings**; your SIEM or landing zone must.
The `guardduty-non-archived-findings` pack rule turns non-compliant on findings left open too long. In the FedRAMP
Moderate pack the limits are 1 day for high, 7 for medium and 30 for low (pack parameters).

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

## Contacts and escalation (fill in)

| Role | Name / team | Primary contact | Backup | When to engage |
|---|---|---|---|---|
| Incident lead (on call) | | | | Every playbook |
| ISSO / security officer | | | | Guardrail or budget changes, risk acceptance, every confirmed incident |
| Enclave platform owner (IaC) | | | | Redeploys, containment drift |
| Landing-zone / Config / GuardDuty owner | | | | Playbooks 4 and 6 when the landing zone owns the service |
| IdP owner | | | | Playbook 7 |
| Tenant app owner | | | | Playbooks 1, 2, 7 |
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
- [ ] Missing alerting added where this incident had none (guardrail, CloudTrail / Config delivery, GuardDuty
      routing, topic subscriptions).
- [ ] Reporting obligations met and recorded (IR-6); privacy / legal informed where PII or PHI was involved.
- [ ] Evidence filed with the incident record. Prompt text only where the incident lead requires it.
- [ ] Playbook and contacts table updated; lessons fed into the next incident-response exercise.
