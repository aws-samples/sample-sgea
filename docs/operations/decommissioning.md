# Decommissioning

How to retire a production enclave (or one tenant) without losing records you are obliged to keep. The enclave is
built to resist deletion — Object Lock, AWS Backup vault lock and a deny-deletion vault policy, deletion protection on
Aurora and the token ledger, `RETAIN` removal policies in the CDK app — so a plain `terraform destroy` /
`cdk destroy` fails or leaves resources behind, by design.

> `tools/sandbox_teardown.py` is **sandbox only**. It bypasses Object Lock GOVERNANCE retention, deletes AWS Backup
> recovery points and earlier final snapshots, and refuses to run unless the credentials' account equals
> `--account-id`. Use it as the reference for **order**, never on a production account. The production order below
> follows it, with the record-keeping steps added and the data-destroying steps made explicit decisions.

Related: [key and secret management](key-and-secret-management.md), [incident response](incident-response.md),
[access review](access-review.md), [change and upgrade](change-and-upgrade.md).

## 1. Why the order matters

| Rule | Why (observed in sandbox runs, `tools/sandbox_teardown.py`) |
|---|---|
| Tenants first | Tenant runtimes, gateway targets, Cedar policies and the policies tenants attached to `sgea-<env>-agentcore-gateway` reference enclave resources |
| Evidence before anything is changed | The as-deployed configuration can only be read while it exists |
| Reset the AgentCore token vault to the service-managed key **before** the enclave CMK is scheduled for deletion | The token vault is **account-wide**. `SetTokenVaultCMK` must decrypt with the current key: a vault left on a deleted key can never be switched again, which blocks every future enclave in the account. CDK resets it when the stack is deleted (the token-vault custom resource's `onDelete`). Terraform does **not**: `aws_bedrockagentcore_token_vault_cmk` has a no-op delete, so `terraform destroy` leaves the vault on the enclave CMK and also schedules that key for deletion — reset the vault explicitly first |
| Decommission as a principal exempt from the audit-protection SCP | Where the SGEA SCP bundles are deployed, `DenyAuditTampering` denies `cloudtrail:DeleteTrail` / `StopLogging`, `config:StopConfigurationRecorder` / `DeleteConfigurationRecorder` / `DeleteDeliveryChannel`, `guardduty:DeleteDetector`, `securityhub:DisableSecurityHub`, `access-analyzer:DeleteAnalyzer`, `logs:DeleteLogGroup` on `/sgea/*`, and `kms:ScheduleKeyDeletion` / `DisableKey` / `PutKeyPolicy` on keys tagged `sgea:profile`. Only the CDK bootstrap execution role (`cdk-hnb659fds-cfn-exec-role-*`), `sgea-*-break-glass` and the principals in `policies.org_policy_exempt_principal_arns` are exempt. Anyone else fails part-way through the teardown |
| Stop the AWS Config recorder **before** deleting the delivery channel | AWS Config refuses to delete a delivery channel while its recorder records (CDK stack delete fails `NotStabilized`). Only where the enclave owns the recorder (`create_config_recorder = true`) |
| Logging stays up until last | CloudTrail, AWS Config and S3 access logging keep writing to the stores until they are destroyed themselves; buckets refill while the stack is deleting |
| Object Lock buckets cannot be emptied before retention ends | The log store and its replica use Object Lock in GOVERNANCE mode with the profile's `logging.retention_days` default retention. Removing a locked version early needs `s3:BypassGovernanceRetention` — which defeats the record-retention control; do not do it in production |
| KMS keys last, with a 30-day deletion window | Every store, backup, snapshot and log group is encrypted with the enclave CMK (replica: the replica CMK). Deleting a key makes everything still encrypted under it unreadable. Keys enter a 30-day pending-deletion window (`deletion_window_in_days = 30` / `pendingWindow`), cancellable until it ends |
| AgentCore ENIs linger | AgentCore leaves ENIs in the runtime subnets for a while after a runtime is deleted; deleting the VPC / subnets can fail with `DependencyViolation` — retry later |

## 2. Before you start

1. **Approval and notice.** Decommissioning approval from the system owner and ISSO / authorizing official;
   notice to every tenant team; freeze changes.
2. **Choose the decommissioning principals** (section 1). `cdk destroy` runs in CloudFormation as the CDK bootstrap execution role, which is exempt. `terraform destroy` runs as your pipeline role, which must be listed in `policies.org_policy_exempt_principal_arns` (if it is not, add it, re-export and re-apply the SCP bundles first). The manual calls (stop the recorder in section 3 step 4, schedule the keys in step 9) need a person on an exempt principal: the break-glass role `sgea-<env>-break-glass` (it is deleted with the enclave, so it cannot be used for step 9 with CDK) or a principal listed in `policies.org_policy_exempt_principal_arns`. Do not detach the SCPs to get through; if you must, do it as a recorded, time-boxed change in the management account. Tell the security team that the teardown raises many `sgea-<env>-ct-*` alarms (trail, Config, KMS, IAM, network changes) until the monitoring layer itself is gone.
3. **Records decision** (section 4): for each store below decide *retain until <date>* or *destroy now*, with the
   retention obligation that drives it. Record the decision.

| Store | Name | Holds |
|---|---|---|
| Log store (+ cross-region replica) | `sgea-<env>-logs-<account>-<region>`, `sgea-<env>-logs-replica-<account>-<replica-region>` | CloudTrail, Bedrock model-invocation logs (Object Lock when `most_sensitive_store`) |
| AWS Config delivery bucket | `sgea-<env>-config-<account>-<region>` | Configuration history and snapshots |
| Access-log sinks | `sgea-<env>-access-logs-<account>-<region>` (both regions) | S3 server access logs of the log store |
| CloudWatch log groups | `/sgea/<env>/cloudtrail`, `/sgea/<env>/bedrock/model-invocations`, `/sgea/<env>/agentcore`, `/sgea/<env>/vpc-flow-logs`, `/aws/lambda/sgea-<env>-*`, `/aws/bedrock-agentcore/runtimes/*` | Logs at `log_retention_days` |
| Trace spans (with `manage_transaction_search`) | `aws/spans` (account-wide; created by X-Ray, not by the IaC, so it survives the destroy) | OpenTelemetry spans of the agents, encrypted with the enclave CMK once the post-deploy step ran |
| AWS Backup vault | `sgea-<env>` | Recovery points (vault lock, deny-deletion policy) |
| Aurora | `sgea-<env>-vector` (final snapshot `sgea-<env>-vector-final`) | Vector store / knowledge-base data |
| Token ledger | `sgea-token-usage-<env>` | Usage per user / team (chargeback evidence) |
| AgentCore Memory | `sgea_<env>_memory` | Conversation events (event expiry applies) |
| ECR | `sgea-<env>-agents` | Agent images |

4. **Final evidence** (read-only), kept in your records system:
   - As-deployed configuration: `python3 tools/collect_evidence.py --profile profiles/<profile>.json --engine terraform|cdk --env <env> --out <your evidence dir>`.
   - Final conformance-pack results: `aws configservice describe-conformance-pack-compliance --conformance-pack-name <pack>`
     per pack.
   - The last `resolved_profile.json`, `MANUAL-STEPS.md`, `OPERATIONS.md`, Terraform state / CDK outputs, and the
     decommissioning change record.
5. If a retained store must outlive the account (account closure), copy it to the customer records system first and
   verify the copy; keep the key material needed to read it.

## 3. Production teardown order

1. **Offboard tenants.** Destroy each tenant stack (runtimes, gateway targets, Cedar policies, tool Lambdas, their
   policies attached to `sgea-<env>-agentcore-gateway`). AgentCore runtime deletion can report `NotStabilized` once;
   wait and retry. Remove tenant IdP app clients.
2. **Collect final evidence** (section 2 step 4) if not done.
3. **Token vault.** If the account's AgentCore token vault uses the enclave CMK
   (`get-token-vault` → `kmsConfiguration.keyType = CustomerManagedKey` with the enclave key), set it back to the
   service-managed key — the API call `tools/sandbox_teardown.py` makes is
   `set_token_vault_cmk(kmsConfiguration={"keyType": "ServiceManagedKey"})` on `bedrock-agentcore-control`. It needs
   an SDK / CLI that includes `bedrock-agentcore-control`; do **not** continue if it cannot run. Other workloads in
   the account using the vault are affected: coordinate.
   - **Terraform: required.** `terraform destroy` does not touch the vault (no-op delete) and schedules the enclave CMK for deletion in the same run, so a vault not reset here stays on a key that is about to be deleted.
   - **CDK:** `cdk destroy` resets the vault to `ServiceManagedKey` when it deletes the token-vault custom resource. Resetting it here as well is harmless; at the latest, confirm with `get-token-vault` after step 7 and before step 9.
4. **AWS Config recorder** (only where the enclave owns it): stop recorder `sgea-<env>`
   (`stop_configuration_recorder`, as the exempt principal from section 2 step 2: the audit-protection SCP denies it to everyone else). This ends AWS Config recording for the account and region — do it after the final
   evidence, and only if no landing-zone control depends on it.
5. **Lift deletion protections — only for what you decided to destroy:**
   - Aurora `sgea-<env>-vector`: deletion protection off. The destroy takes final snapshot `sgea-<env>-vector-final`
     (`skip_final_snapshot = false`). A snapshot with that name from an earlier destroy blocks the next one —
     rename / copy it; never delete the last backup to make room.
   - Token ledger `sgea-token-usage-<env>`: deletion protection off.
   - DoD IL4 / IL5: Network Firewall `sgea-<env>-vdss` delete protection off.
   - AWS Backup vault `sgea-<env>`: recovery points are protected by the vault lock (`min_retention_days` = the pack
     backup retention) and an access policy denying `backup:DeleteRecoveryPoint`. **Leave both in place** while any
     recovery point is inside its retention; the vault (and its key) stays until the last one expires.
6. **Buckets.** Buckets you keep: remove them from the IaC deliberately (they are `RETAIN` in the CDK app). Buckets you
   destroy: empty all versions and delete markers once retention has ended (Object Lock buckets) — logging writes
   until the trail, Config and access logging are gone, so empty again if the destroy step fails on a non-empty
   bucket. Empty ECR `sgea-<env>-agents` if it is destroyed.
7. **Destroy the enclave** as the exempt principal (section 2 step 2).
   - Terraform: `terraform destroy` in `build/<profile-id>/terraform` (one root; both regions). It deletes the trail, the recorder, the analyzers and the `/sgea/*` log groups it manages, and schedules the enclave CMK for deletion — all denied by the audit-protection SCP unless the pipeline role is exempt. The token vault must already be reset (step 3). With
     `deploy_org_policies = true` this also detaches and deletes the `sgea-scp-N` / `sgea-rcp-N` bundles — run from
     the management account, and confirm no other account depends on them.
   - CDK: `npx cdk destroy --all -c sgea:env=<env> ...` (same context as the deploy). CloudFormation then leaves the
     `RETAIN` resources: log groups, buckets, ECR repository, token ledger, KMS keys, backup vault;
     Aurora is snapshotted. Inventory them and delete, or keep, per the records decision.
8. **Leftovers that block a later redeploy** (names are fixed): Aurora's exported log group
   `/aws/rds/cluster/sgea-<env>-vector/...`, retained log groups, ECR repository, backup vault, ledger table.
   The `aws/spans` log group is created by X-Ray and stays after the destroy (encrypted with the enclave CMK if the post-deploy step ran). If CloudWatch Transaction Search should stay on for other workloads, move its log group to another key before step 9; otherwise turn it off (`aws xray update-trace-segment-destination --destination XRay`) so spans stop arriving, then keep or delete `aws/spans` per the records decision.
9. **KMS keys, last** (Terraform has already scheduled them in step 7; CDK retains them). Only when nothing you keep is encrypted under them (stores, replica, recovery points,
   snapshots, log groups, `aws/spans`, the token vault), and as a principal exempt from the audit-protection SCP (the enclave key is tagged `sgea:profile`; the break-glass role no longer exists at this point): schedule deletion of the enclave CMK (`alias/sgea-<env>`, description
   `SGEA enclave CMK (<env>)`) and the replica CMK (description `SGEA log replica CMK (<env>)`, replica region) with
   the 30-day window. Expect `kms-cmk-not-scheduled-for-deletion` NON_COMPLIANT during the window if the packs are
   still deployed. If any record must stay readable, keep the key enabled until that record's retention ends.
10. **Network and account** (customer-owned): VPC / subnets after the AgentCore ENIs are gone; CDK bootstrap stacks
    in both regions; account closure or reuse per the landing zone.

**One tenant only:** step 1 for that tenant, then remove its users / groups and app clients from the IdP, its
policies from `sgea-<env>-agentcore-gateway`, its Cedar policies or interceptor rules, its images from
`sgea-<env>-agents`; keep its log data per section 4 (it is in the shared enclave stores).

## 4. Retention obligations (general)

SGEA configures retention but does not decide your records schedule. The values SGEA sets come from the profile:
`logging.retention_days` (FedRAMP Low 90, Moderate 365, High / DoD IL4 / IL5 1,095, FDA Part 11 2,555 days in the
shipped baselines; CloudWatch values are rounded up), and the AWS Backup retention from the composed packs (see the
facts table in `OPERATIONS.md`). Confirm the obligation that applies to *your* records with your records officer,
counsel and ISSO before destroying anything.

| Framework | What to keep at decommissioning (general) |
|---|---|
| FedRAMP / NIST SP 800-53 (AU-11, SI-12, MP-6) | Audit records for the organization-defined retention period and your agency's records schedule; sanitize or crypto-erase media holding federal data when no longer needed; keep the authorization package and final ConMon artifacts |
| DoD SRG (IL2 / IL4 / IL5) | As FedRAMP, plus DoD records-management and mission-owner / CSSP requirements; coordinate the disconnect (BCAP) and the authorization close-out with the authorizing official |
| HIPAA | Required documentation (policies, risk analyses, assessments, activity reviews) for six years from creation or last effective date; PHI disposal under the device and media controls; BAA termination terms for any PHI still held |
| HITRUST | Evidence supporting the current certification until the certification period and any inheritance obligations end |
| FDA 21 CFR Part 11 | Electronic records and their audit trails for the retention period of the governing predicate rule, readable and available for inspection — including the means to read them (keys, formats) |

## 5. Sign-off checklist

| # | Item | Evidence | Done |
|---|---|---|---|
| 1 | Decommissioning approved by system owner and ISSO / AO; tenants notified | Approval record | [ ] |
| 2 | Records decision per store (retain-until date or destroy) with the obligation cited | Decision record | [ ] |
| 3 | Final as-deployed evidence, pack results, resolved profile, state / outputs archived | Evidence archive | [ ] |
| 4 | Retained data copied out where it outlives the account; copy verified | Copy verification | [ ] |
| 5 | All tenants offboarded; gateway-role tenant policies, Cedar policies / interceptor rules, IdP clients removed | Tenant checklist | [ ] |
| 6 | Token vault on the service-managed key (or confirmed not on the enclave CMK) before any key deletion — Terraform: reset explicitly before `terraform destroy`; CDK: confirmed after `cdk destroy` | `get-token-vault` output | [ ] |
| 6a | Teardown run by a principal exempt from the audit-protection SCP; security team told to expect the `-ct-` alarms; SCPs not detached (or detached only by a recorded, time-boxed change) | Change record | [ ] |
| 7 | Config recorder stopped only if enclave-owned, after final evidence | Change record | [ ] |
| 8 | No Object Lock retention bypassed; no recovery point deleted inside its retention | Bucket / vault review | [ ] |
| 9 | Aurora final snapshot exists and is retained per the records decision | Snapshot id | [ ] |
| 10 | Enclave destroyed; `RETAIN` leftovers inventoried and either deleted or kept with owner | Inventory | [ ] |
| 11 | SCP / RCP bundles detached / deleted from the management account (if deployed) | Organizations record | [ ] |
| 12 | KMS keys scheduled for deletion only after nothing kept depends on them; window end date recorded | Key ids, dates | [ ] |
| 13 | Remaining access to retained stores limited and assigned to an owner | Access-review record | [ ] |
| 14 | SSP / inventory / POA&M updated; authorization closed out | Package update | [ ] |
