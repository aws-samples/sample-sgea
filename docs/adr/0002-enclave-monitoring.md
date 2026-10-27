# ADR 0002 — Enclave monitoring, audit protection and break-glass

Status: accepted (2026-10-26). Both engines implement this exactly: same resource names, alarm names, thresholds, event patterns and toggles. Names use `<env>` (Terraform `var.env`, CDK `sgea:env`).

## Context

The enclave emitted three CloudWatch alarms (its own Lambdas) and no event routing. Gaps found while writing the runbooks: no alerting on security findings, compliance drift, backup or rotation failures, audit-trail tampering, Bedrock / AgentCore health or cost; no IAM Access Analyzer; no SCP protection for the audit trail and the enclave key; no break-glass role; CloudWatch Transaction Search and the `aws/spans` log group unmanaged; the CDK token-vault custom resource has no delete handler.

## Decision

A new layer **`enclave-monitoring`** (Terraform module `modules/enclave-monitoring`, CDK construct `EnclaveMonitoring` in `lib/constructs/monitoring.ts`) plus changes in `policy_library.py`, the enclave key policy and the CDK token vault. Every notification goes to the existing CMK-encrypted SNS topic `sgea-<env>-security-alarms`.

### Toggles (landing zone may own these)

| Terraform variable | CDK context | Default | Controls |
|---|---|---|---|
| `manage_monitoring` | `sgea:manageMonitoring` | `true` | the whole layer |
| `create_access_analyzer` | `sgea:createAccessAnalyzer` | `true` | external-access analyzer (ACCOUNT) |
| `create_unused_access_analyzer` | `sgea:createUnusedAccessAnalyzer` | `false` | unused-access analyzer (paid; 90-day threshold) |
| `manage_transaction_search` | `sgea:manageTransactionSearch` | `true` | Transaction Search (log resource policy + TransactionSearchConfig) |
| `monthly_budget_usd` | `sgea:monthlyBudgetUsd` | `0` (off) | AWS Budgets cost budget (commercial partition only) |
| `create_cost_anomaly_monitor` | `sgea:createCostAnomalyMonitor` | `false` | Cost Anomaly Detection (commercial partition only; an account allows one SERVICE monitor and AWS often creates a default one, so it is opt-in) |
| `create_break_glass_role` | `sgea:createBreakGlassRole` | `false` | break-glass role (needs `break_glass_principal_arns`) |
| `break_glass_principal_arns` | `sgea:breakGlassPrincipalArns` (comma list) | `[]` | who may assume it |
| `guardrail_intervention_threshold` | `sgea:guardrailInterventionThreshold` | `50` | guardrail-interventions alarm threshold (per 15 min) |

In the `aws-us-gov` partition Budgets and Cost Anomaly Detection are skipped (billing lives in the commercial payer account).

### M1 — Event routing (EventBridge → SNS)

Rules named `sgea-<env>-evt-<name>`, default event bus, target the alarm topic.

| Name | Event pattern |
|---|---|
| `guardduty` | source `aws.guardduty`, detail-type `GuardDuty Finding`, `detail.severity` numeric >= 7 |
| `securityhub` | source `aws.securityhub`, detail-type `Security Hub Findings - Imported`, `detail.findings.Severity.Label` in [HIGH, CRITICAL], `detail.findings.Workflow.Status` = [NEW] |
| `inspector` | source `aws.inspector2`, detail-type `Inspector2 Finding`, `detail.severity` in [HIGH, CRITICAL] |
| `config-compliance` | source `aws.config`, detail-type `Config Rules Compliance Change`, `detail.newEvaluationResult.complianceType` = [NON_COMPLIANT] |
| `backup` | source `aws.backup`, detail-type in [Backup Job State Change, Copy Job State Change, Restore Job State Change], `detail.state` in [FAILED, ABORTED, EXPIRED] |
| `secret-rotation` | source `aws.secretsmanager`, detail-type `AWS Service Event via CloudTrail`, `detail.eventName` = [RotationFailed] |
| `access-analyzer` | source `aws.access-analyzer`, detail-type `Access Analyzer Finding`, `detail.status` = [ACTIVE] (only when an analyzer is created) |
| `stack-drift` | CDK only: source `aws.cloudformation`, detail-type `CloudFormation Drift Detection Status Change`, `detail.status-details.stack-drift-status` = [DRIFTED] |

Topic policy (it replaces SNS's default policy, so it also keeps `cloudwatch.amazonaws.com` `sns:Publish` with `aws:SourceAccount` for the alarms): allow `events.amazonaws.com` `sns:Publish` with `aws:SourceAccount` = account and `aws:SourceArn` like `arn:<partition>:events:<region>:<account>:rule/sgea-<env>-evt-*`; allow `budgets.amazonaws.com` and `costalerts.amazonaws.com` `sns:Publish` with `aws:SourceAccount` = account (when created). Enclave key policy: new statement `EventDeliveryToEncryptedSns` allowing `events.amazonaws.com` (and, in the commercial partition only, `budgets.amazonaws.com` and `costalerts.amazonaws.com`) `kms:GenerateDataKey*` and `kms:Decrypt` with `aws:SourceAccount` = account.

CDK drift detection: an EventBridge Scheduler schedule `sgea-<env>-drift-detect` (rate 1 day) with the universal target `arn:aws:scheduler:::aws-sdk:cloudformation:detectStackDrift` for each SGEA stack, role `sgea-<env>-drift-scheduler` with `cloudformation:DetectStackDrift` and `cloudformation:DetectStackResourceDrift` on the SGEA stacks plus the AWS managed `ReadOnlyAccess` policy (drift detection reads every resource in the stack); trust `scheduler.amazonaws.com` with `aws:SourceAccount` and `aws:SourceArn` = the `default` schedule-group ARN (Scheduler sets the group ARN, not the schedule ARN; sandbox 2026-10-26). The log-replica stack is in another region and is not scheduled. Terraform: no in-account resource; `OPERATIONS.md` documents a scheduled `terraform plan -detailed-exitcode` in the customer's pipeline.

### M2 — CloudTrail metric filters and alarms

On the enclave trail log group (`/sgea/<env>/cloudtrail`), metric filter `sgea-<env>-ct-<name>`, metric `<name>` in namespace `SGEA/<env>/CloudTrail`, value 1, each with an alarm `sgea-<env>-ct-<name>`: statistic Sum, period 300 s, 1 evaluation period, threshold >= 1, `treat_missing_data = notBreaching`, alarm action the topic.

| Name | Filter pattern |
|---|---|
| `unauthorized-api` | `{ ($.errorCode = "*UnauthorizedOperation") \|\| ($.errorCode = "AccessDenied*") }` |
| `console-no-mfa` | `{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }` |
| `root-usage` | `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }` |
| `iam-policy-changes` | `{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "Put*Policy") \|\| ($.eventName = "Delete*Policy") \|\| ($.eventName = "Create*Policy*") \|\| ($.eventName = "Attach*Policy") \|\| ($.eventName = "Detach*Policy")) }` |
| `cloudtrail-changes` | `{ ($.eventName = "CreateTrail") \|\| ($.eventName = "UpdateTrail") \|\| ($.eventName = "DeleteTrail") \|\| ($.eventName = "StartLogging") \|\| ($.eventName = "StopLogging") \|\| ($.eventName = "PutEventSelectors") }` |
| `console-auth-failures` | `{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }` |
| `kms-key-disable-or-delete` | `{ ($.eventSource = "kms.amazonaws.com") && (($.eventName = "DisableKey") \|\| ($.eventName = "ScheduleKeyDeletion")) }` |
| `s3-bucket-policy-changes` | `{ ($.eventSource = "s3.amazonaws.com") && (($.eventName = "PutBucketAcl") \|\| ($.eventName = "PutBucketPolicy") \|\| ($.eventName = "PutBucketCors") \|\| ($.eventName = "PutBucketLifecycle") \|\| ($.eventName = "PutBucketReplication") \|\| ($.eventName = "DeleteBucketPolicy") \|\| ($.eventName = "DeleteBucketCors") \|\| ($.eventName = "DeleteBucketLifecycle") \|\| ($.eventName = "DeleteBucketReplication")) }` |
| `config-changes` | `{ ($.eventSource = "config.amazonaws.com") && (($.eventName = "StopConfigurationRecorder") \|\| ($.eventName = "DeleteDeliveryChannel") \|\| ($.eventName = "PutDeliveryChannel") \|\| ($.eventName = "PutConfigurationRecorder") \|\| ($.eventName = "DeleteConfigurationRecorder")) }` |
| `security-group-changes` | `{ ($.eventName = "AuthorizeSecurityGroupIngress") \|\| ($.eventName = "AuthorizeSecurityGroupEgress") \|\| ($.eventName = "RevokeSecurityGroupIngress") \|\| ($.eventName = "RevokeSecurityGroupEgress") \|\| ($.eventName = "CreateSecurityGroup") \|\| ($.eventName = "DeleteSecurityGroup") }` |
| `nacl-changes` | `{ ($.eventName = "CreateNetworkAcl") \|\| ($.eventName = "CreateNetworkAclEntry") \|\| ($.eventName = "DeleteNetworkAcl") \|\| ($.eventName = "DeleteNetworkAclEntry") \|\| ($.eventName = "ReplaceNetworkAclEntry") \|\| ($.eventName = "ReplaceNetworkAclAssociation") }` |
| `network-gateway-changes` | `{ ($.eventName = "CreateCustomerGateway") \|\| ($.eventName = "DeleteCustomerGateway") \|\| ($.eventName = "AttachInternetGateway") \|\| ($.eventName = "CreateInternetGateway") \|\| ($.eventName = "DeleteInternetGateway") \|\| ($.eventName = "DetachInternetGateway") }` |
| `route-table-changes` | `{ ($.eventSource = "ec2.amazonaws.com") && (($.eventName = "CreateRoute") \|\| ($.eventName = "CreateRouteTable") \|\| ($.eventName = "ReplaceRoute") \|\| ($.eventName = "ReplaceRouteTableAssociation") \|\| ($.eventName = "DeleteRouteTable") \|\| ($.eventName = "DeleteRoute") \|\| ($.eventName = "DisassociateRouteTable")) }` |
| `vpc-changes` | `{ ($.eventName = "CreateVpc") \|\| ($.eventName = "DeleteVpc") \|\| ($.eventName = "ModifyVpcAttribute") \|\| ($.eventName = "AcceptVpcPeeringConnection") \|\| ($.eventName = "CreateVpcPeeringConnection") \|\| ($.eventName = "DeleteVpcPeeringConnection") \|\| ($.eventName = "RejectVpcPeeringConnection") \|\| ($.eventName = "AttachClassicLinkVpc") \|\| ($.eventName = "DetachClassicLinkVpc") \|\| ($.eventName = "DisableVpcClassicLink") \|\| ($.eventName = "EnableVpcClassicLink") }` |
| `organizations-changes` | `{ ($.eventSource = "organizations.amazonaws.com") && (($.eventName = "AcceptHandshake") \|\| ($.eventName = "AttachPolicy") \|\| ($.eventName = "CreateAccount") \|\| ($.eventName = "CreatePolicy") \|\| ($.eventName = "DeletePolicy") \|\| ($.eventName = "DetachPolicy") \|\| ($.eventName = "LeaveOrganization") \|\| ($.eventName = "MoveAccount") \|\| ($.eventName = "RemoveAccountFromOrganization") \|\| ($.eventName = "UpdatePolicy")) }` |
| `break-glass-assumed` | only with the break-glass role: `{ ($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "<break-glass role ARN>") }` |

(`\|\|` above is a literal `||` in the pattern; the backslash only escapes the Markdown table.)

### M3 — Service health alarms

Alarm names `sgea-<env>-<name>`, action the topic, `treat_missing_data = notBreaching` unless stated.

| Name | Metric | Dimensions | Statistic / period / evaluation | Threshold |
|---|---|---|---|---|
| `bedrock-throttles` | `AWS/Bedrock` `InvocationThrottles` | none (account aggregate) | Sum / 300 / 2 of 2 | >= 10 |
| `bedrock-server-errors` | `AWS/Bedrock` `InvocationServerErrors` | none | Sum / 300 / 1 | >= 5 |
| `bedrock-invocation-log-delivery` | `AWS/Bedrock` `ModelInvocationLogsCloudWatchDeliverySuccess` | none | Minimum / 900 / 1 | < 1 (missing = notBreaching) — only where model-invocation logging is on |
| `guardrail-interventions` | `AWS/Bedrock/Guardrails` `InvocationsIntervened` | `GuardrailArn` = baseline guardrail ARN, `GuardrailVersion` = its version | Sum / 900 / 1 | >= 50 (variable `guardrail_intervention_threshold`) |
| `gateway-system-errors` | `AWS/Bedrock-AgentCore` `SystemErrors` | `Operation` = InvokeGateway, `Protocol` = MCP, `Resource` = gateway ARN | Sum / 300 / 1 | >= 5 — only where the gateway exists |
| `gateway-throttles` | `AWS/Bedrock-AgentCore` `Throttles` | same | Sum / 300 / 2 of 2 | >= 10 — only where the gateway exists |

Dimensions verified against the sandbox account's published metrics (2026-10-26).

### M4 — Cost

Budget `sgea-<env>-monthly-cost` (COST, MONTHLY, `monthly_budget_usd`), notifications ACTUAL > 80 % and FORECASTED > 100 %, subscriber the topic. Cost Anomaly Detection: monitor `sgea-<env>-services` (DIMENSIONAL, SERVICE) and subscription `sgea-<env>-anomalies` (IMMEDIATE, SNS subscriber the topic, threshold expression: `ANOMALY_TOTAL_IMPACT_ABSOLUTE` >= 100).

### M5 — IAM Access Analyzer

`sgea-<env>-external-access` (type `ACCOUNT`); optional `sgea-<env>-unused-access` (type `ACCOUNT_UNUSED_ACCESS`, unused access age 90 days). Findings route through M1 `access-analyzer`.

### M6 — Transaction Search

The enclave cannot create `aws/spans`: log-group names starting with `aws/` are reserved (CreateLogGroup `InvalidParameterException`, sandbox 2026-10-26). X-Ray creates it with the first spans. After the first spans arrive, put `aws/spans` under the enclave CMK and the pack retention (`aws logs associate-kms-key --log-group-name aws/spans --kms-key-id <enclave CMK ARN>`, `aws logs put-retention-policy --log-group-name aws/spans --retention-in-days <days>`); if AWS rejects either for this reserved group, record it as a documented exception for `cloudwatch-log-group-encrypted` / `cw-loggroup-retention-period-check`. CloudWatch Logs resource policy `sgea-<env>-transaction-search` allowing `xray.amazonaws.com` `logs:PutLogEvents` on `aws/spans:*` and `/aws/application-signals/data:*` with `aws:SourceAccount` and `aws:SourceArn` like `arn:<partition>:xray:<region>:<account>:*`; then `AWS::XRay::TransactionSearchConfig` (Terraform `awscc_xray_transaction_search_config`) with `IndexingPercentage = 1`. When `manage_transaction_search` is true, `MANUAL-STEPS.md` keeps only the post-deploy CMK / retention step for `aws/spans`.

### Audit protection SCP (policy_library)

New statement group in the SCP bundles, `DenyAuditTampering`, applied to all principals except `aws:PrincipalArn` matching the enclave deployment role(s) and break-glass role (`arn:<partition>:iam::*:role/sgea-*-break-glass` plus a new input `org_policy_exempt_principal_arns`): deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors`, `config:StopConfigurationRecorder`, `config:DeleteConfigurationRecorder`, `config:DeleteDeliveryChannel`, `guardduty:DeleteDetector`, `guardduty:DisassociateFromAdministratorAccount`, `securityhub:DisableSecurityHub`, `access-analyzer:DeleteAnalyzer`, `logs:DeleteLogGroup` on `/sgea/*` log groups; deny `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:PutKeyPolicy` where `aws:ResourceTag/sgea:profile` exists. The bundles must stay within ≤ 4 SCPs and the 5,120-character limit per policy.

### Break-glass role

Optional `sgea-<env>-break-glass`: trust `break_glass_principal_arns` with `aws:MultiFactorAuthPresent = true` and `aws:MultiFactorAuthAge < 3600`, `max_session_duration = 3600`, AWS managed `AdministratorAccess` attached (no inline policy), tagged `sgea:role = break-glass`. Every assumption raises `sgea-<env>-ct-break-glass-assumed`. Post-use review: `docs/operations/access-review.md`.

### CDK token vault

The token-vault custom resource gets an `onDelete` call that sets the vault back to the service-managed key (`SetTokenVaultCMK` with `keyType = ServiceManagedKey`), so `cdk destroy` leaves the account usable. The custom-resource policy allows `SetTokenVaultCMK` on `token-vault/default` and on `/identities/set-token-vault-cmk` (the resource AWS evaluates; sandbox 2026-10-26). Terraform already handles this through the resource lifecycle; verify and document.

## Consequences

- Alert volume: the CIS-style filters and Config compliance changes are noisy in a busy account; customers tune thresholds or disable rules through the toggles.
- Cost: metric filters and alarms (about 25 alarms), an optional unused-access analyzer, Budgets / Cost Anomaly Detection (no charge for these two at default use), Transaction Search indexing at 1 %.
- Sandbox (HITRUST, both engines, 2026-10-27): deploy, e2e 7/7 and teardown pass with the layer on. Alarm / event delivery to the topic and the SCP were not exercised.
- The audit-protection exemption matches role names (`sgea-*-break-glass`, `cdk-hnb659fds-cfn-exec-role-*`) across accounts, so a principal that can create IAM roles could name one to match and bypass the denies. Planned hardening: exempt exact, account-scoped role ARNs (from the target account ids) and deny creating or re-trusting roles with those names outside the exempt principals. Until then, restrict `iam:CreateRole` in the landing zone. Terraform has no fixed deployment role: list the pipeline role in `org_policy_exempt_principal_arns`, or applies that change the trail, recorder or enclave key are denied.
