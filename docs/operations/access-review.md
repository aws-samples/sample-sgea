# Access review

Quarterly review of who and what can act in the enclave account: IAM roles and policies, the identity provider
(Cognito or the organization IdP), KMS key policies, resource policies, and the emergency (break-glass) path. The
generated `build/<profile-id>/OPERATIONS.md` schedules it (section 3, quarterly) and lists the signed review as
continuous-monitoring evidence. All steps are read-only.

`<env>` is the env name of the deploy (Terraform `var.env`, CDK `-c sgea:env`), `<account>` the enclave account.

Related: [tenant onboarding](tenant-onboarding.md), [key and secret management](key-and-secret-management.md),
[incident response](incident-response.md).

## 1. Procedure

1. **Inventory.** List the roles in the account whose names start with `sgea-<env>-` or `SgeaEnclave` (the same
   filter `tools/collect_evidence.py` uses), plus every other role and Identity Center permission set with access to
   the account. Compare with section 2 and with the tenant register (one entry per onboarded tenant).
2. **For each enclave role:** trust policy unchanged (service principal and `aws:SourceAccount` / `aws:SourceArn`
   conditions as listed); attached policies are the expected ones; **no inline policies**
   (`iam-no-inline-policy-check`; the evidence collector reports "roles with inline policies"); last-used date is
   plausible. Any extra attachment is a finding unless a change record explains it.
3. **For each tenant role:** owner still active; policy still scoped to the tenant's own resources (section 3 of
   [tenant onboarding](tenant-onboarding.md)); tagged `sgea:tenant`.
4. **Identity provider** (section 3).
5. **KMS key policies and grants** (section 4).
6. **Resource policies** (section 5).
7. **Break-glass** (section 6): role exists, MFA enforced, alarm armed, every use since the last review has a
   post-use review.
8. **IAM Access Analyzer** (section 6a): every active finding of `sgea-<env>-external-access` (and of `sgea-<env>-unused-access`, if turned on) is resolved, archived with a reason, or ticketed.
9. **Record** findings, removals and approvals; reviewer and ISSO sign. Removals go through change control
   ([change and upgrade](change-and-upgrade.md)) when they touch IaC-managed resources.

## 2. Roles the emitters create

Names are fixed by the emitters (Terraform modules and CDK constructs use the same names unless noted).

| Role | Trusted by | Purpose | Expected permissions |
|---|---|---|---|
| `sgea-<env>-agentcore-gateway` | `bedrock-agentcore.amazonaws.com` (this account, AgentCore ARNs) | Gateway service role | Gateway config encryption on the enclave CMK; policy-engine read / authorize (where the policy engine is used); invoke `sgea-<env>-tool-policy` (where the interceptor runs). **Plus one invoke policy per tenant tool**, attached by tenant stacks — review each |
| `sgea-<env>-agentcore-memory` | `bedrock-agentcore.amazonaws.com` (same conditions) | Memory strategies | `bedrock:InvokeModel*` on foundation models / inference profiles; enclave CMK |
| `sgea-<env>-log-replication` | `s3.amazonaws.com` | Log store cross-region replication | Read source versions, replicate to the replica bucket, decrypt enclave CMK, encrypt with the replica CMK |
| `sgea-<env>-bedrock-invocation-logging` | `bedrock.amazonaws.com` | Model-invocation logs to CloudWatch (when `model_invocation_logging`) | Write `/sgea/<env>/bedrock/model-invocations` |
| `sgea-<env>-cloudtrail-to-cloudwatch` (Terraform; CDK: CloudFormation-named `SgeaEnclave-*`) | `cloudtrail.amazonaws.com` | Trail delivery to `/sgea/<env>/cloudtrail` | Create stream / put events on that group |
| `sgea-<env>-vpc-flow-logs` | `vpc-flow-logs.amazonaws.com` | Flow logs to `/sgea/<env>/vpc-flow-logs` (enclave network; in IL4 / IL5 the DoD SCCA module — CDK there: CloudFormation-named `SgeaEnclave-*`) | Write that log group |
| `sgea-<env>-backup` | `backup.amazonaws.com` | AWS Backup plan `sgea-<env>` | AWS managed backup / restore policies (S3 backup / restore where S3 is protected) |
| Execution roles of `sgea-<env>-tool-policy` and `sgea-<env>-token-meter` | `lambda.amazonaws.com` | Gateway interceptor; token meter | One customer-managed policy each (`sgea-<env>-tool-policy-function` / `sgea-<env>-token-meter-function` in Terraform) + `AWSLambdaVPCAccessExecutionRole` + `AWSXRayDaemonWriteAccess`; enclave CMK, own DLQ, ledger `GetItem` (interceptor) / `UpdateItem`, `PutItem` (meter) |
| CDK deploy helpers (custom-resource providers, propagation waits) | `lambda.amazonaws.com` | Deployment-time API calls only (tagged `sgea:role=deploy-helper`) | Scoped to the calls they make (e.g. `SetTokenVaultCMK` / `GetTokenVault` on the account's token vault) |
| `AWSServiceRoleForConfig` | AWS Config (service-linked) | Created by the enclave only when `create_config_recorder = true` | AWS managed |
| `sgea-<env>-break-glass` (only with `create_break_glass_role` / CDK `sgea:createBreakGlassRole`) | The principals in `break_glass_principal_arns` (CDK `sgea:breakGlassPrincipalArns`), with `aws:MultiFactorAuthPresent = true` and `aws:MultiFactorAuthAge < 3600` | Emergency access for people (section 6); tagged `sgea:role = break-glass` | AWS managed `AdministratorAccess` only, no inline policy; maximum session 1 hour |
| `sgea-<env>-drift-scheduler` (CDK only) | `scheduler.amazonaws.com` (this account, schedule `sgea-<env>-drift-detect`) | Daily CloudFormation drift detection on the SGEA stacks | Customer-managed `sgea-<env>-drift-scheduler` (`cloudformation:DetectStackDrift`, `DetectStackResourceDrift` on the SGEA stacks) + AWS managed `ReadOnlyAccess` (drift detection reads every resource in the stack) |

Lambda execution roles and CDK helper roles have generated names: in CDK they start with `SgeaEnclave`; in Terraform
the `terraform-aws-modules/lambda` module creates them for the function. Identify them from each function's `Role`.

Tenant roles follow the tenant's naming (sample: `sgea-<env>-sample-agent` and its tool function role). Services
enabled by the enclave (GuardDuty, Security Hub, Amazon Inspector, AgentCore) may create their own service-linked
roles; confirm they belong to an enabled service.

Organization layer (only with `deploy_org_policies = true`): the SCP / RCP bundles `sgea-scp-N` / `sgea-rcp-N` in the
management account. Review their attachments (`org_target_ids`) and any `scp_policy_documents` overrides there.

## 3. Identity provider: users, groups, clients

The enclave creates no IAM users and no user pool. End users authenticate through the JWT authorizers: per tenant
runtime (`jwt_discovery_url`, `jwt_allowed_clients`, `jwt_allowed_audience`) and, when set, the enclave gateway
(`agent_jwt_discovery_url` / `agent_jwt_allowed_clients`, CDK `jwtDiscoveryUrl` / `jwtAllowedClients`).

| Check | Why |
|---|---|
| Every allowed client id in the runtime and gateway authorizers maps to an active, approved tenant app | A stale client can still obtain tokens the enclave accepts |
| Users are current (leavers disabled), MFA enforced | Inbound auth is the only gate on runtime invocation (SGEA-AC-RT-04) |
| Group membership in the team claim (`token_control.team_claim`, default `cognito:groups`) is correct; each user in one team group | The first value selects the per-team monthly budget and attribution |
| Interceptor rules that match on claims (`tool_policy`, GovCloud) still name existing groups | A renamed group silently loses (or keeps) tool access |
| No test identity provider in production (the sample's `sgea-<env>-sample-test-idp` user pool is for sandboxes) | Test pools allow password auth with optional MFA |

For an organization IdP (e.g. Entra ID) do these checks there; for Cognito, in the user pool.

## 4. KMS key policies and grants

Read each key policy (`get_key_policy`, policy name `default` — the evidence collector records the statement ids)
and compare with the expected set. Any other statement is a finding.

| Key | Expected statements |
|---|---|
| Enclave CMK `alias/sgea-<env>` (description `SGEA enclave CMK (<env>)`) | Account root administration (IAM-delegated); `CloudWatchLogs` (`logs.<region>.amazonaws.com`, this account's log groups); `CloudTrail` (this account's trails); `ConfigDelivery` (`AWSServiceRoleForConfig`); `ConfigServicePrincipal`, `BedrockInvocationLogDelivery`, `S3EventNotificationsToEncryptedSns`, `CloudWatchAlarmsToEncryptedSns`, `EventDeliveryToEncryptedSns` (`events.amazonaws.com`; in the commercial partition also `budgets.amazonaws.com` and `costalerts.amazonaws.com`) (service principals, `aws:SourceAccount` = this account) |
| Replica CMK (replica region; description `SGEA log replica CMK (<env>)`; CDK alias `alias/sgea-<env>-log-replica`) | Account root administration only |

Because the root statement delegates to IAM, also review **IAM policies that grant use of the key**: the enclave
roles in section 2, tenant roles (`kms:Decrypt` / `kms:GenerateDataKey` on `kms_key_arn` only), and any human role.
No customer-managed policy may allow blocked KMS actions on all keys (`iam-customer-policy-blocked-kms-actions`).
Review the key's grants too: AWS services (e.g. Aurora, DynamoDB, AgentCore) create grants for the resources they
encrypt; a grant to an unknown principal is a finding. Key handling itself: [key and secret management](key-and-secret-management.md).

## 5. Resource policies

| Resource | Expected |
|---|---|
| Tenant AgentCore runtimes | One statement `AllowOnlyThroughEnclaveEndpoints`: `Principal *`, `bedrock-agentcore:InvokeAgentRuntime`, condition `aws:SourceVpce` = the enclave endpoint(s). No policy at all means SGEA-AC-ID-04 is unmet (JWT still required); any statement without the `aws:SourceVpce` condition is a finding |
| Log store `sgea-<env>-logs-*` | TLS-only deny; `CloudTrailAclCheck` / `CloudTrailWrite` (`aws:SourceArn` = the enclave trail); `BedrockInvocationLogWrite` (`aws:SourceAccount`, Bedrock ARNs) |
| Config bucket `sgea-<env>-config-*` | TLS-only deny; `ConfigBucketCheck`, `ConfigDelivery` (`AWS:SourceAccount`), `ConfigServiceLinkedRole` |
| Access-log sinks, replica buckets | TLS-only deny; S3 server-access-log delivery (sinks) |
| SNS `sgea-<env>-log-store-events` | `S3EventNotifications`: `s3.amazonaws.com` publish, this account, `arn:...:s3:::sgea-<env>-*` |
| SNS `sgea-<env>-security-alarms` | `OwnerAccess` (this account); `CloudWatchAlarms` (`cloudwatch.amazonaws.com`, `aws:SourceAccount`); with the monitoring layer `EventBridgeRules` (`events.amazonaws.com`, `aws:SourceArn` like `rule/sgea-<env>-evt-*`) and, when the budget or anomaly monitor is created, `Budgets` / `CostAnomalyDetection` (`aws:SourceAccount`). Review **subscribers** — they receive every security alarm and routed finding |
| CloudWatch Logs resource policy `sgea-<env>-transaction-search` (with `manage_transaction_search`) | `xray.amazonaws.com` `logs:PutLogEvents` on `aws/spans` and `/aws/application-signals/data` only, `aws:SourceAccount` and `aws:SourceArn` of this account |
| AWS Backup vault `sgea-<env>` | `DenyRecoveryPointDeletion` (deny `backup:DeleteRecoveryPoint`, `UpdateRecoveryPointLifecycle`, `PutBackupVaultAccessPolicy` to everyone) still present |
| ECR `sgea-<env>-agents` | No repository policy (the emitters create none) |
| Lambda functions | No function policy granting public or cross-account invoke (`lambda-function-public-access-prohibited`); the gateway invokes through its role, not a function policy |

Changes to any of these outside IaC are also drift: the next `terraform plan` / CDK change set shows them.

## 6. Break-glass (emergency access)

SGEA can create the emergency role for you; it is off by default. The enclave's other roles are service roles and are not for people.

**The SGEA role (optional).** Set `create_break_glass_role = true` and `break_glass_principal_arns` (CDK `-c sgea:createBreakGlassRole=true -c sgea:breakGlassPrincipalArns=<arn>,<arn>`); `terraform plan` and `cdk synth` fail if the role is requested without principals. The role `sgea-<env>-break-glass`:

- trusts only the listed principals, and only with MFA (`aws:MultiFactorAuthPresent = true`) used within the last hour (`aws:MultiFactorAuthAge < 3600`);
- has a maximum session duration of 1 hour;
- has the AWS managed `AdministratorAccess` policy attached and no inline policy, and is tagged `sgea:role = break-glass`;
- raises the alarm `sgea-<env>-ct-break-glass-assumed` on every `AssumeRole` (a CloudTrail metric filter on `/sgea/<env>/cloudtrail`, Sum >= 1 in 5 minutes, to `sgea-<env>-security-alarms`; incident response [playbook 11](incident-response.md#11-break-glass-role-assumed));
- is exempt from the audit-protection SCP statements (`DenyAuditTampering`: stopping or changing the trail and the Config recorder, deleting GuardDuty / Security Hub / Access Analyzer or `/sgea/*` log groups, and `kms:ScheduleKeyDeletion` / `DisableKey` / `PutKeyPolicy` on keys tagged `sgea:profile`), so that it can recover the audit trail and the enclave key. The other SGEA SCPs still apply to it.

**SCP exemption caveat.** The audit-protection exemption matches role **names** across accounts (`arn:<partition>:iam::*:role/sgea-*-break-glass`, `arn:<partition>:iam::*:role/cdk-hnb659fds-cfn-exec-role-*`, plus `policies.org_policy_exempt_principal_arns`). A principal that can create IAM roles could create a role with a matching name and bypass the denies. Until SGEA exempts exact, account-scoped role ARNs (planned, ADR 0002), restrict `iam:CreateRole` and trust-policy changes for these names in your landing zone, and check in this review that every role matching the patterns is one you expect (step below).

**Bring your own role.** If you keep `create_break_glass_role = false`, design an equivalent customer-owned role outside the enclave IaC (landing zone or identity account) with the same properties: a small named group, MFA on assumption, a short session, an alarm on every use. Publishing to `sgea-<env>-security-alarms` reaches the existing subscribers (the topic is encrypted with the enclave CMK; the publisher needs use of the key). Name it `sgea-<env>-break-glass` only if you want it exempt from the audit-protection SCP. If the access path uses IAM users, they fall under the account baseline rules the enclave leaves to the customer (`iam-user-mfa-enabled`, `root-account-hardware-mfa-enabled`, `iam-user-unused-credentials-check`, ...) — prefer IAM Identity Center or federation with phishing-resistant MFA.

**Operate it**

1. **Keep the principal list short.** Review `break_glass_principal_arns` each quarter: named people or one small emergency group, owners still in role.
2. **Scope deliberately.** `AdministratorAccess` can lift enclave protections (`s3:BypassGovernanceRetention`, Backup vault policy changes, key deletion). Use it only under a declared incident or emergency change, and get two-person approval for any change to a retention or key protection.
3. **Test the alarm.** Assume the role at least once a year in a planned exercise (it can be part of the `response-plan-tested` exercise) and confirm the alarm reached the subscribers.
4. **Store credentials offline** (if any) with split custody.
5. **Post-use review** within one business day: who, why, the incident or change ticket, every action taken (from CloudTrail; the Logs Insights query in incident response playbook 11), any resource changed outside IaC (re-run `terraform plan` / CloudFormation drift detection to find drift and reconcile), credentials rotated, and ISSO sign-off. Record it with this quarter's access review.

**Quarterly checks**

```bash
aws iam get-role --role-name sgea-<env>-break-glass \
    --query 'Role.[MaxSessionDuration,AssumeRolePolicyDocument]'
aws iam list-attached-role-policies --role-name sgea-<env>-break-glass   # AdministratorAccess only
aws iam list-role-policies --role-name sgea-<env>-break-glass            # empty
aws cloudwatch describe-alarms --alarm-names sgea-<env>-ct-break-glass-assumed --query 'MetricAlarms[].[StateValue,AlarmActions]'
# Roles whose names match an audit-protection exemption pattern: each must be expected
aws iam list-roles --query "Roles[?ends_with(RoleName, '-break-glass') || starts_with(RoleName, 'cdk-hnb659fds-cfn-exec-role-')].[RoleName,CreateDate]" --output table
```

## 6a. IAM Access Analyzer findings

The enclave creates the analyzer `sgea-<env>-external-access` (type `ACCOUNT`, `create_access_analyzer` / CDK `sgea:createAccessAnalyzer`, default on) and, optionally, `sgea-<env>-unused-access` (type `ACCOUNT_UNUSED_ACCESS`, unused for 90 days; `create_unused_access_analyzer` / `sgea:createUnusedAccessAnalyzer`, default off, charged per role and user). Active external-access findings are also routed to `sgea-<env>-security-alarms` (`sgea-<env>-evt-access-analyzer`; incident response [playbook 12](incident-response.md#12-security-hub-inspector-or-access-analyzer-finding)). Each quarter:

```bash
aws accessanalyzer list-findings-v2 --analyzer-arn arn:aws:access-analyzer:<region>:<account>:analyzer/sgea-<env>-external-access \
    --filter '{"status":{"eq":["ACTIVE"]}}' --query 'findings[].[id,resourceType,resource]' --output table
aws accessanalyzer list-findings-v2 --analyzer-arn arn:aws:access-analyzer:<region>:<account>:analyzer/sgea-<env>-unused-access \
    --filter '{"status":{"eq":["ACTIVE"]}}' --query 'findings[].[id,findingType,resource]' --output table   # if created
aws accessanalyzer list-archive-rules --analyzer-name sgea-<env>-external-access
```

- Every **active** finding is either a mistake (remove the access through the IaC or the tenant's pipeline) or intended (archive it with the reason and a ticket).
- Every **archive rule** is still justified: an archive rule hides future findings of the same shape.
- Unused roles, keys and permissions (unused-access analyzer, or last-used dates where it is off) are removed or justified; feed them into section 1, step 2.
- Where the landing zone runs an organization analyzer instead (`create_access_analyzer = false`), review the findings for this account there.

## 7. Review record

| # | Item | Result | Reviewer |
|---|---|---|---|
| 1 | Enclave roles match section 2; no inline policies; trust policies unchanged | | |
| 2 | Policies on `sgea-<env>-agentcore-gateway` beyond the enclave's: one per active tenant tool | | |
| 3 | Tenant roles: owner active, scoped, tagged `sgea:tenant` | | |
| 4 | Human access (Identity Center / roles): least privilege, leavers removed | | |
| 5 | IdP: allowed clients, users, MFA, team groups, interceptor claim rules | | |
| 6 | KMS key policies match section 4; grants and IAM key permissions reviewed | | |
| 7 | Resource policies match section 5; alarm-topic subscribers current | | |
| 8 | SCP / RCP attachments and overrides (management account), if deployed | | |
| 9 | Break-glass: role, MFA, principal list, alarm tested, every use reviewed; roles matching the SCP exemption patterns all expected | | |
| 10 | IAM Access Analyzer: no unexplained active finding; archive rules justified; unused access removed or justified | | |
| 11 | Findings ticketed; sign-off by reviewer and ISSO | | |
