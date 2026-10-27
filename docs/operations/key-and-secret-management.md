# Key and secret management

How the enclave's keys and secrets are set up, what depends on them, and how to operate them safely. This includes
how to cancel a key deletion and the token-vault ordering rule that broke a sandbox run. Names use `<env>`,
`<account>`, `<region>` (primary) and `<replica-region>`. Settings are quoted from the emitted IaC
(`emitters/terraform_emitter.py` module `enclave-kms`, `emitters/cdk_app/lib/constructs/enclave-kms.ts`,
`replica-stack.ts`, `agentcore-platform.ts`, `enclave-aurora.ts`).

## Inventory

| Item | Identifier | Created by | Protects |
|---|---|---|---|
| Enclave CMK | alias `alias/sgea-<env>`, description `SGEA enclave CMK (<env>)` | `enclave-kms`, unless you supply your own (`kms_key_arn` / CDK `-c sgea:kmsKeyArn`) | Nearly everything in the primary region (next table) |
| Log replica CMK | description `SGEA log replica CMK (<env>)`. CDK also creates the alias `alias/sgea-<env>-log-replica` and the SSM parameter `/sgea/<env>/log-replica-key-arn` (replica region) | `enclave-logging` (Terraform `aws_kms_key.replica`) / `SgeaEnclaveLogReplica` stack | Replica bucket `sgea-<env>-logs-replica-<account>-<replica-region>` and its access-log sink |
| Aurora admin secret (RDS-managed) | RDS-managed secret of cluster `sgea-<env>-vector` (user `sgea_admin`) | `enclave-aurora` | Aurora admin credential |
| AgentCore token vault key setting | `token-vault/default` (one per account and region) | Terraform `aws_bedrockagentcore_token_vault_cmk`, CDK `Custom::SgeaTokenVaultCmk` | Outbound credentials stored by AgentCore Identity (SGEA-AC-ID-01) |
| JWT issuer keys, client ids and secrets | Your IdP (`agent_jwt_discovery_url`, `agent_jwt_allowed_clients`; CDK `sgea:jwtDiscoveryUrl`, `sgea:jwtAllowedClients`) | Not the enclave | Inbound authentication to the gateway and runtimes |

**What the enclave CMK encrypts:**

- the log store and the AWS Config store (SSE-KMS)
- CloudTrail
- the `/sgea/<env>/*` and enclave Lambda log groups, the Aurora `postgresql` log group, and VPC flow logs
- both SNS topics (`sgea-<env>-security-alarms`, `sgea-<env>-log-store-events`) and both dead-letter queues
- the token ledger `sgea-token-usage-<env>`
- Aurora storage, Performance Insights and the RDS-managed admin secret
- ECR `sgea-<env>-agents`
- the guardrail, the AgentCore gateway, the policy engine and memory, and the token vault
- the Lambda environment variables
- the AWS Backup vault `sgea-<env>`
- EBS default encryption (when `manage_account_baseline`)

The access-log sinks use SSE-S3 (`AES256`), because S3 server-access-log delivery does not support SSE-KMS targets.

## 1. Enclave CMK

| Setting | Value in the IaC |
|---|---|
| Rotation | `enable_key_rotation = true` / `enableKeyRotation: true`. No custom period is set, so KMS rotates yearly (the README says "annual rotation") |
| Deletion window | `deletion_window_in_days = 30` / `pendingWindow: 30 days` |
| Removal | CDK `RemovalPolicy.RETAIN`: `cdk destroy` leaves the key. Terraform `destroy` schedules deletion with the 30-day window |
| Multi-region | **No.** Neither engine creates a multi-region key or replica key. The replica region has its own independent CMK with the same rotation and 30-day window. S3 replication re-encrypts replicas with it (`replica_kms_key_id`), so the replica stays readable if the primary key is lost |
| Plan-time check | `sgea check` requires `enable_key_rotation = true` (`cmk-backing-key-rotation-enabled`) and that the key is in the plan (`kms-cmk-not-scheduled-for-deletion`). The live state is checked by AWS Config |

### Key-policy statements (by Sid)

Both engines emit the same statements. All service statements use `Resource: "*"` (the key itself).

| Sid | Principal | Actions | Condition | Allows |
|---|---|---|---|---|
| `Default` (Terraform). The CDK default statement has no Sid | Account root | `kms:*` | — | Key administration and use through IAM policies in this account. Every role that uses the key gets access this way: DynamoDB, RDS, Lambda, SQS, ECR, AgentCore, Backup, the replication role. For example the gateway role's `EnclaveKeyViaAgentCore` / `GatewayConfigEncryption` and the functions' `EnclaveKey` |
| `CloudWatchLogs` | `logs.<region>.amazonaws.com` | `kms:Encrypt*`, `kms:Decrypt*`, `kms:ReEncrypt*`, `kms:GenerateDataKey*`, `kms:Describe*` | `ArnLike kms:EncryptionContext:aws:logs:arn = arn:<partition>:logs:<region>:<account>:*` | Encrypted log groups in this account and region only |
| `CloudTrail` | `cloudtrail.amazonaws.com` | `kms:GenerateDataKey*`, `kms:DescribeKey` | `StringLike kms:EncryptionContext:aws:cloudtrail:arn = arn:<partition>:cloudtrail:*:<account>:trail/*` | Trail log-file encryption for this account's trails. Readers decrypt through IAM (`Default`) |
| `ConfigDelivery` | `AWSServiceRoleForConfig` (the AWS Config service-linked role, named directly, no wildcard) | `kms:GenerateDataKey*`, `kms:Decrypt` | — | AWS Config delivery to the SSE-KMS Config store |
| `ConfigServicePrincipal` | `config.amazonaws.com` | `kms:Decrypt`, `kms:GenerateDataKey` | `aws:SourceAccount = <account>` | AWS Config's delivery-channel writability check (it runs as the service principal; verified in the sandbox) |
| `BedrockInvocationLogDelivery` | `bedrock.amazonaws.com` | `kms:GenerateDataKey*`, `kms:Decrypt` | `aws:SourceAccount = <account>` | Model-invocation log delivery to the log store |
| `S3EventNotificationsToEncryptedSns` | `s3.amazonaws.com` | `kms:GenerateDataKey*`, `kms:Decrypt` | `aws:SourceAccount = <account>` | S3 publishing `s3:ObjectRemoved:*` events to `sgea-<env>-log-store-events` |
| `CloudWatchAlarmsToEncryptedSns` | `cloudwatch.amazonaws.com` | `kms:GenerateDataKey*`, `kms:Decrypt` | `aws:SourceAccount = <account>` | Alarms publishing to `sgea-<env>-security-alarms` |
| `EventDeliveryToEncryptedSns` | `events.amazonaws.com`; in the commercial partition also `budgets.amazonaws.com` and `costalerts.amazonaws.com` | `kms:GenerateDataKey*`, `kms:Decrypt` | `aws:SourceAccount = <account>` | EventBridge rules `sgea-<env>-evt-*`, AWS Budgets and Cost Anomaly Detection publishing to `sgea-<env>-security-alarms` (ADR 0002) |

The replica CMK's policy is only account administration. In Terraform that is the Sid `AccountAdministration`
(root, `kms:*`); in CDK it is the default key policy.

**Bring your own key** (`kms_key_arn` / `sgea:kmsKeyArn`). SGEA then creates no enclave key, and your key policy
must grant the same service statements. Without them CloudTrail, AWS Config, Bedrock logging, S3 notifications,
alarm and event delivery fail. Tag your key `sgea:profile` if you want the audit-protection SCP (section 2) to cover it. The AWS Config service-linked role must exist before the key policy names it.

### Inspect and rotate

```bash
aws kms describe-key --key-id alias/sgea-<env> --query 'KeyMetadata.[KeyId,KeyState,KeyManager,MultiRegion,DeletionDate]'
aws kms get-key-rotation-status --key-id alias/sgea-<env>
aws kms list-key-rotations --key-id alias/sgea-<env>            # history of rotations
aws kms get-key-policy --key-id alias/sgea-<env> --policy-name default --query Policy --output text | jq '.Statement[].Sid'
aws kms rotate-key-on-demand --key-id alias/sgea-<env>          # only if the ISSO requires an out-of-cycle rotation
```

Rotation keeps the key id and ARN and keeps the old key material for decryption, so nothing needs re-encrypting.
That includes the token vault. **Replacing** the key (a new ARN) is a migration, not a rotation. Several resources
cannot change their key in place (Aurora storage encryption, for example). Plan it as a rebuild, and move the
token vault (section 3) while the old key is still enabled.

## 2. A key scheduled for deletion

While a key is `PendingDeletion` it cannot be used. **Every dependency in the inventory fails at once:**

- CloudTrail and AWS Config delivery stop.
- Log groups stop ingesting.
- The token ledger is unreadable, so the gateway interceptor denies every tool call
  (`token ledger unavailable (fail closed)`).
- Aurora loses access to its storage key.
- **The alarm topic is encrypted with the same key, so alarms are not delivered.**

When the window ends, the key and everything encrypted only with it are gone for good. That includes the AWS Backup
recovery points in `sgea-<env>`. Only the replica bucket (replica CMK) survives.

**Detection**

- The AWS Config rule `kms-cmk-not-scheduled-for-deletion` (managed rule `KMS_CMK_NOT_SCHEDULED_FOR_DELETION`). It is
  in the FedRAMP Low / Moderate / High, HIPAA Security, FDA Part 11, NIST 800-53 Rev 5 and CMMC 2.0 L2 packs and
  reports the key NON_COMPLIANT.
- CloudTrail `ScheduleKeyDeletion` events, and the alarm `sgea-<env>-ct-kms-key-disable-or-delete` (any key disabled or scheduled for deletion; incident response playbook 8).
- Do not rely on the SNS alarm topic for the enclave key itself. The topic shares the key, so once the key is disabled or pending deletion that alarm (and every other one) cannot be delivered; it does reach you for other keys.
- **Prevention.** Where the SGEA SCP bundles are deployed, the audit-protection statement `DenyAuditTamperingEnclaveKeys` denies `kms:ScheduleKeyDeletion`, `kms:DisableKey` and `kms:PutKeyPolicy` on every key tagged `sgea:profile` (the enclave keys carry the tag) to every principal except the CDK bootstrap execution role (`cdk-hnb659fds-cfn-exec-role-*`), `sgea-*-break-glass` and the principals in `policies.org_policy_exempt_principal_arns`. A deletion that got through came from one of those, from the management account, or from a role named to match the pattern (the exemption matches role names; ADR 0002). Without the SGEA SCPs, check whether your landing zone's guardrails deny these calls.

```bash
aws kms describe-key --key-id <key-id> --query 'KeyMetadata.[KeyState,DeletionDate,Description]'
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion \
    --query 'Events[].[EventTime,Username,Resources[0].ResourceName]' --output text
```

**Cancel the deletion**

1. Cancel it. The key returns in state `Disabled`:
   `aws kms cancel-key-deletion --key-id <key-id>`
2. Enable it: `aws kms enable-key --key-id <key-id>`
3. Confirm `Enabled`: `aws kms describe-key --key-id <key-id> --query KeyMetadata.KeyState`
4. CDK: if the alias was deleted with the stack, re-create it by redeploying. Then confirm with
   `aws kms list-aliases --key-id <key-id>`.
5. Confirm the dependents have recovered:
   - CloudTrail and Config delivery: `incident-response.md`, playbook 4.
   - Token meter heartbeat: playbook 3. Invoke the meter once.
   - Aurora status: `aws rds describe-db-clusters --db-cluster-identifier sgea-<env>-vector --query 'DBClusters[0].Status'`.
6. Re-evaluate the Config rule (Config console → Conformance packs → Re-evaluate, or
   `aws configservice start-config-rules-evaluation` with the pack's rule name). Record the event as an incident
   (`incident-response.md`).

The sandbox teardown (`tools/sandbox_teardown.py`, sandbox only) finds the keys to delete by description
(`SGEA...(<env>)`), because `cdk destroy` keeps them. It schedules them with the 30-day window **after** the token vault
reset. Production decommissioning follows the order in section 3.

## 3. AgentCore token vault and the CMK

The token vault is **account-wide** (`arn:<partition>:bedrock-agentcore:<region>:<account>:token-vault/default`).
The enclave points it at the enclave CMK. Every enclave `<env>` in the same account and region shares this one
setting, and the last deploy wins.

- **`SetTokenVaultCMK` must decrypt with the key the vault uses now** (sandbox 2026-10-15). It runs with the caller's
  own KMS permissions. The CDK custom resource grants `kms:DescribeKey`, `kms:CreateGrant`, `kms:Decrypt`,
  `kms:Encrypt`, `kms:GenerateDataKey` and `kms:GenerateDataKeyWithoutPlaintext` on the key. If the current key is
  pending deletion or deleted, **no later deploy can switch the vault**. On 2026-10-21 a Terraform run failed with
  `creating Bedrock AgentCore Token Vault CMK`, because the vault still referenced the previous run's CMK, which was
  pending deletion.
- **Switch the vault back to the service-managed key BEFORE you schedule the CMK for deletion.** The engines differ:
  - **CDK:** the token-vault custom resource `Custom::SgeaTokenVaultCmk` has an `onDelete` call (`SetTokenVaultCMK` with `keyType = ServiceManagedKey`), so `cdk destroy` resets the vault while the key still exists (CDK retains the key). Confirm with `get-token-vault` before you schedule the key.
  - **Terraform:** `aws_bedrockagentcore_token_vault_cmk` has a **no-op delete** in the `aws` provider, so `terraform destroy` leaves the vault on the enclave CMK and schedules that key for deletion in the same run. **Reset the vault yourself before `terraform destroy`** (commands below).
  - The SGEA sandbox teardown resets the vault explicitly on both engines, and stops before deleting anything if the SDK cannot.

```bash
aws bedrock-agentcore-control get-token-vault --region <region> --query kmsConfiguration
aws bedrock-agentcore-control set-token-vault-cmk --region <region> --kms-configuration keyType=ServiceManagedKey
```

**Decommissioning order (production)**

1. Remove the tenant apps and collect evidence.
2. Confirm no other `<env>` in the account and region still uses the vault.
3. Switch the vault to `ServiceManagedKey` and confirm with `get-token-vault`. Terraform: required before the destroy. CDK: `cdk destroy` does it, but resetting first is harmless; confirm after the destroy either way.
4. Only then destroy the enclave and schedule the key for deletion (its 30-day window), as a principal exempt from the audit-protection SCP (section 2; `decommissioning.md`, section 2).

**Repair when the vault references a key that is pending deletion** (what fixed the sandbox on 2026-10-21):

1. `aws kms cancel-key-deletion --key-id <old-key>`, then `aws kms enable-key --key-id <old-key>`.
2. `set-token-vault-cmk --kms-configuration keyType=ServiceManagedKey`, or point the vault at the new key.
3. Re-schedule the old key for deletion only if it is really retired (as an exempt principal where the audit-protection SCP applies):
   `aws kms schedule-key-deletion --key-id <old-key> --pending-window-in-days 30`.

## 4. Aurora admin secret (RDS-managed)

| Setting | Value in the IaC |
|---|---|
| Managed by RDS | `manage_master_user_password = true` / `manageMasterUserPassword: true`. No password is in the code or state (checked by cfn-guard) |
| Encryption | `master_user_secret_kms_key_id` / `masterUserSecret.kmsKeyId` = the enclave CMK |
| User | `sgea_admin` (non-default, `rds-instance-default-admin-check`) |
| Other access | IAM database authentication and the RDS Data API are on. The Bedrock knowledge base uses `credentials_secret_arn` |
| Rotation | RDS rotates the managed secret. SGEA sets no schedule, so the RDS default applies. Pack rules: `secretsmanager-rotation-enabled-check`, `secretsmanager-using-cmk`. `secretsmanager-scheduled-rotation-success-check` is `runtime-only` (outcome visible live only) |

```bash
SECRET=$(aws rds describe-db-clusters --db-cluster-identifier sgea-<env>-vector \
    --query 'DBClusters[0].MasterUserSecret.SecretArn' --output text)     # Terraform: module output secret_arn
aws secretsmanager describe-secret --secret-id "$SECRET" \
    --query '[RotationEnabled,RotationRules,LastRotatedDate,NextRotationDate,KmsKeyId]'
aws secretsmanager rotate-secret --secret-id "$SECRET"                  # rotate now (suspected exposure)
```

Use the admin credential for administration only. Applications should use IAM authentication or the Data API.
Callers that fetch the secret each time it is used are unaffected by rotation. If the enclave CMK is unavailable,
the secret cannot be read (section 2).

## 5. Cognito / JWT authorizer keys and client secrets

The enclave holds **no signing keys and no client secrets** for inbound authentication.

- The runtimes use a custom JWT authorizer (`discovery_url`, `allowed_clients`). The gateway uses one when a JWT
  issuer is set (`CUSTOM_JWT`), otherwise `AWS_IAM` (SigV4).
- AgentCore resolves the issuer's signing keys from the OIDC discovery document, so **key rotation is the IdP's
  job**. Publish the new key before you sign with it, and keep the old key published until its tokens have expired.
- Client ids are pinned in `jwt_allowed_clients` / `agent_jwt_allowed_clients` (CDK `sgea:jwtAllowedClients`). A new
  or rotated client id means a profile/input change and a redeploy. Removing an id blocks every user of that client
  (`incident-response.md`, playbook 7).
- The sample tenant's Cognito pool is a test IdP. Its app client has **no secret** (`generate_secret = false`), and
  access and ID tokens last 60 minutes. Production confidential clients belong to the IdP and the tenant. Keep
  their secrets in Secrets Manager (customer-managed key, rotation on); SGEA does not emit them.
- Tokens reach the gateway interceptor (`pass_request_headers = true`) so it can read claims. The interceptor never
  logs them. It logs only `user`, `team` and `client_id`.
- Outbound credentials that agents use to call third-party tools are stored in the AgentCore token vault (section 3)
  under the enclave CMK.

## Periodic review

| When | Check | Command / source | Expected |
|---|---|---|---|
| Daily (automate) | No enclave key pending deletion or disabled | `kms-cmk-not-scheduled-for-deletion` in the packs; `aws kms describe-key --key-id alias/sgea-<env>`, and the replica key in `<replica-region>` | `Enabled`, rule COMPLIANT |
| Monthly | Key rotation on, rotations happening | `aws kms get-key-rotation-status`, `list-key-rotations` (both keys) | `KeyRotationEnabled: true`; last rotation within 12 months |
| Monthly | Key policy unchanged | `get-key-policy` Sids compared with section 1; CloudTrail `PutKeyPolicy` | Same 9 statements, no wildcard principal |
| Monthly | Token vault on the current enclave CMK | `aws bedrock-agentcore-control get-token-vault` | `CustomerManagedKey`, `kmsKeyArn` = `alias/sgea-<env>` target |
| Monthly | Aurora secret rotating | `describe-secret` (section 4); `secretsmanager-*` pack rules | `RotationEnabled: true`, `LastRotatedDate` within the schedule |
| Quarterly | Who can use or administer the keys | IAM policies granting `kms:*` / `kms:ScheduleKeyDeletion` / `kms:PutKeyPolicy` on the enclave key (IAM Access Analyzer, policy review); the principals exempt from the audit-protection SCP (`access-review.md`, section 6) | Pipeline and break-glass roles only |
| Quarterly | IdP signing-key and client review | IdP admin console; `agent_jwt_allowed_clients` in the deployed inputs | Only approved client ids; signing keys rotated per IdP policy |
| Before any decommission or key replacement | Token-vault ordering | Section 3 | Vault on `ServiceManagedKey` (or the new key) before the old key is scheduled |
| Yearly (exercise) | Cancel-deletion and restore drill in a sandbox | Section 2; restore one recovery point from `sgea-<env>` | Drill recorded with times |

**Controls:** SC-12, SC-13, SC-28, IA-5, AC-2, AU-9, CP-9, CM-6.
