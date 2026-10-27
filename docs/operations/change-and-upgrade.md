# Change and upgrade

How to change a deployed enclave: upgrade the SGEA toolkit, refresh the AWS conformance packs, change the profile
(e.g. token budgets, guardrail settings) or change an environment input. Every change goes the same way: re-export,
diff, `sgea verify`, `sgea check` against a real plan / template, review, apply, re-evaluate, update evidence.

> **Not yet validated.** SGEA's sandbox validation covers fresh deploys and teardown only. An **in-place upgrade of
> a running enclave** (apply a newer export over an existing one) **has not been sandbox-validated** on either
> engine. Until it is, rehearse every upgrade on a non-production enclave deployed from the *current* export, then
> apply the *new* export over it, before touching production.
>
> The monitoring layer (`enclave-monitoring`, ADR 0002) is new in this release and has not been sandbox-validated on either engine yet; rehearse its first apply the same way (section 3a).

Related: [key and secret management](key-and-secret-management.md), [incident response](incident-response.md),
[decommissioning](decommissioning.md), and the generated `build/<profile-id>/OPERATIONS.md` / `MANUAL-STEPS.md`.

## 1. Kinds of change

| Change | What moves | Where it starts |
|---|---|---|
| SGEA toolkit upgrade | Emitters, wrapper modules / constructs, Lambda code (`emitters/lambda/`), catalogs, dispositions, known findings | New toolkit version (`sgea --version`) |
| AWS conformance-pack refresh | Pinned templates in `sources/conformance-packs/`, then `catalog/` and `docs/CONTROL-COVERAGE.md` | Maintainer: section 2 |
| Profile change | `resolved_profile.json` (e.g. `token_control`, `guardrails`, `logging.retention_days`) | `profiles/<profile>.json` or a baseline |
| Environment input change | Terraform variables / CDK `-c sgea:<name>` (VPC, subnets, `agent_jwt_allowed_clients`, `tool_policy`, ...) | Your tfvars / `cdk.context.json` |
| Provider / CDK library bump | `.terraform.lock.hcl`, `cdk/package-lock.json` | `terraform init -upgrade`, `npm` |
| Monitoring toggles | `manage_monitoring`, `create_access_analyzer`, `create_unused_access_analyzer`, `manage_transaction_search`, `monthly_budget_usd`, `create_cost_anomaly_monitor`, `create_break_glass_role` / `break_glass_principal_arns`, `guardrail_intervention_threshold` (CDK `sgea:<camelCase>`) | Your tfvars / `cdk.context.json` |
| Audit-protection exemptions | `policies.org_policy_exempt_principal_arns` in the resolved profile (the SCP bundles) | `profiles/<profile>.json`, then re-export and re-apply the SCP bundles |

## 2. Refreshing the AWS conformance packs (maintainer)

1. Replace the pinned template(s) `sources/conformance-packs/Operational-Best-Practices-for-<pack>.yaml` with the
   new AWS-published version.
2. `python -I tools/build_catalog.py` — rebuilds `catalog/` and `docs/CONTROL-COVERAGE.md`. It **fails** when a rule
   has neither a plan / CFN mapping nor a disposition; it names the rule.
3. For each new rule, add a Terraform + CFN mapping in `sources/inferred/config-rule-plan-checks.json` (enclave-owned)
   or one disposition in `sources/inferred/rule-dispositions.yaml` (`tenant`, `not-in-enclave`,
   `customer-prerequisite`, `process`, `runtime-only`). Review `sources/inferred/pack-parameter-overlays.json`
   against changed pack parameters (e.g. `ConcurrencyLimitLow`, `requiredRetentionDays`).
4. `pytest -q`, then `sgea verify` for every profile you deploy.
5. ISSO review of every new or changed disposition before the new catalog is used for production.

## 3. Upgrade procedure

1. **Record the current state.** Note the toolkit version (`sgea --version`), keep the current export directory
   (`build/<profile-id>/`) unchanged as the rollback copy, and record the environment inputs exactly as deployed
   (Terraform tfvars; CDK context, including `sgea:env`). Confirm the Terraform state backend is versioned
   (by default the export's `backend.tf` uses `backend "s3"` with key `sgea/<profile-id>/terraform.tfstate`).
2. **Fresh restore point.** Confirm the latest AWS Backup job for vault `sgea-<env>` completed (OPERATIONS.md,
   daily checks) or take an on-demand backup of the Aurora cluster `sgea-<env>-vector` and the token ledger
   `sgea-token-usage-<env>`.
3. **Re-export to a new directory**, never over the deployed copy:

   ```bash
   sgea resolve --profile profiles/<profile>.json            # fails on any violation
   sgea export  --profile profiles/<profile>.json --out build-next/
   ```

   Copy your environment-input files (tfvars, `cdk.context.json`) into the new export unchanged.
4. **Diff the export.** `diff -r build/<profile-id> build-next/<profile-id>` and review, at minimum:
   `resolved_profile.json` (every control decision), `terraform/main.tf` and `terraform/modules/`,
   `cdk/lib/` and `cdk/config.json`, `MANUAL-STEPS.md` (new section 1 prerequisites, e.g. a higher Lambda quota;
   new known findings) and `OPERATIONS.md` (new alarms, cadences).
5. **Credential-free gate:** `sgea verify --out build-next/<profile-id>` must exit 0.
6. **Plan against the real account (read-only) and check it:**

   ```bash
   # Terraform
   cd build-next/<profile-id>/terraform && terraform init && terraform plan -out tfplan \
     && terraform show -json tfplan > plan.json && cd -
   sgea check --out build-next/<profile-id> --plan build-next/<profile-id>/terraform/plan.json

   # CDK: synth with the SAME context as the deployed stacks
   (cd build-next/<profile-id>/cdk && npm ci && npx cdk synth -c sgea:env=<env> -c sgea:vpcId=... ...)
   sgea check --out build-next/<profile-id> --cfn build-next/<profile-id>/cdk/cdk.out/SgeaEnclave.template.json \
                                            --cfn build-next/<profile-id>/cdk/cdk.out/SgeaEnclaveLogReplica.template.json
   ```

   Exit 5 = a required `FAIL` or `GAP`: stop. Decide with the ISSO whether `UNVERIFIED` values are acceptable
   (`--strict` fails on them).
7. **Replacement review** (section 4). For Terraform, search the plan for `must be replaced` / `forces replacement`
   and for every `destroy`. For CDK, review the CloudFormation change set of each stack (`Replacement: True`).
8. **Review gates** (section 5), then apply (section 6).
9. **After the apply** (section 7): re-evaluate the rules, re-run tenant checks, update the evidence.

## 3a. Before the first apply with the monitoring layer

The export now contains the `enclave-monitoring` module / `EnclaveMonitoring` construct, a new key-policy statement (`EventDeliveryToEncryptedSns`), a replaced policy on `sgea-<env>-security-alarms`, the audit-protection statements in the SCP bundles (`DenyAuditTampering`), and, in CDK, an `onDelete` reset on the token-vault custom resource. Before you apply:

1. **Terraform: exempt your pipeline role from the audit-protection SCP first.** Terraform has no fixed deployment role. Add the role your pipeline applies with to `policies.org_policy_exempt_principal_arns` in the profile, re-export, and apply the SCP bundles from the management account **before** (or together with, from the same reviewed export) the enclave change. Otherwise every apply that changes the trail, the Config recorder or delivery channel, a `/sgea/*` log group or the enclave key policy is denied — and this upgrade itself changes the key policy (`kms:PutKeyPolicy`). The CDK bootstrap execution role with the default qualifier (`cdk-hnb659fds-cfn-exec-role-*`) is exempt already; with a custom bootstrap qualifier, list that role too.
2. **Transaction Search.** With `manage_transaction_search` (default on) the enclave installs the X-Ray log resource policy and turns Transaction Search on; X-Ray creates `aws/spans` (the enclave cannot: names starting with `aws/` are reserved). If the landing zone already owns Transaction Search, set it to false. After the first spans arrive, put `aws/spans` under the enclave CMK and the pack retention (`aws logs associate-kms-key --log-group-name aws/spans --kms-key-id <enclave CMK ARN>`, `aws logs put-retention-policy --log-group-name aws/spans --retention-in-days <days>`); if AWS rejects either for this reserved group, record it as a documented exception for `cloudwatch-log-group-encrypted` / `cw-loggroup-retention-period-check`.
3. **Access Analyzer and Cost Anomaly Detection.** If the landing zone runs an organization analyzer and you do not want an account analyzer as well, set `create_access_analyzer` to false. Cost Anomaly Detection is opt-in because an account allows only one per-service monitor and AWS often creates a default one.
4. **Subscriptions and noise.** Subscribe the security team to `sgea-<env>-security-alarms` (`MANUAL-STEPS.md`, after the first deploy), and tell them the first apply raises `sgea-<env>-ct-*` alarms for the IAM, bucket and Config changes it makes.

## 3b. Before the first apply with the token breaker (ADR 0003)

The export adds the token breaker (`sgea-<env>-token-breaker` state machine, rule and roles, the deny policy `sgea-<env>-token-budget-exhausted`, the alarm `sgea-<env>-token-breaker-failures`), new meter permissions and environment, and `stepfunctions` in `services.allow` (so the service allow-list SCP now permits `states:*`). Before you apply:

1. **SCP bundles first.** Apply the updated SCP bundles from the management account before (or together with) the enclave change, or the state machine cannot be created where the old allow-list denies `states:*`.
2. **Tenants tag their runtime roles** `sgea:team = <team>` (TR-26), one team per role. Untagged roles are never touched by the breaker; they stay bounded on the gateway tool path only. Tell tenants whose IaC manages role policy attachments exclusively to exclude the enclave's attachment.
3. **Opt out** with `token_control.model_enforce = false` in the profile if the landing zone already caps Bedrock use per team.
4. **A team already over its monthly budget** is tripped by its next metered model call after the apply, so its model calls are denied within minutes. Check the ledger (`pk=team#<team>`, `sk=month#YYYY-MM`) against `per_team_monthly_tokens` before the apply and agree any override (incident response [playbook 2](incident-response.md#2-token-budget-exhausted-for-a-user-or-team)).

## 4. Disruptive changes

Treat any of these in a plan or change set as a stop-and-review item. "Replacement" means a new resource with a new
id / ARN; data in the old one does not move.

| Change | Effect | What to do |
|---|---|---|
| `env` (Terraform) / `sgea:env` (CDK) changes | Every named resource is `sgea-<env>-*`: the whole enclave is replaced | Never change in place. Treat as a new enclave plus a [decommissioning](decommissioning.md) of the old one |
| Enclave CMK replaced, or `kms_key_arn` switched between "SGEA creates" (null) and "supplied" | Resources whose encryption key is fixed at creation are replaced (e.g. the Aurora cluster, the ECR repository); others re-key only new data | Plan the key change on its own ([key and secret management](key-and-secret-management.md)). The account-wide AgentCore token vault must be moved off the old key while the old key still works. Never schedule the old key for deletion as part of the change |
| Log-store bucket replaced (name inputs, or Object Lock toggled through `logging.most_sensitive_store`) | New bucket; the old one cannot be deleted while objects are under Object Lock retention, so the destroy step fails | Keep the old bucket (it holds records under retention); remove it from the IaC deliberately, do not force it |
| Aurora `sgea-<env>-vector` replaced, or its engine version changes | Replacement = a new, empty cluster. `deletion_protection` makes the destroy step fail (by design) | Never accept an unplanned Aurora replacement. Engine upgrades: follow the RDS upgrade path in a change window with a fresh snapshot |
| AgentCore gateway `sgea-<env>-gateway` or policy engine replaced | New `gateway_id` / `gateway_url` / `gateway_arn` / `policy_engine_id`; tenant gateway targets and Cedar policies are lost | Re-apply every tenant app from the new `enclave` output ([tenant onboarding](tenant-onboarding.md)) |
| Guardrail definition changes | A new immutable guardrail version is created and the old version deleted (`create_before_destroy`); the account-enforced configuration moves to the new version | Re-apply tenant apps with the new `guardrail_version`: agents pinned to the deleted version fail |
| Tenant AgentCore runtime replaced (runtime name, or a changed `agentcore-runtime` wrapper module) | New runtime id / ARN and a new runtime log group `/aws/bedrock-agentcore/runtimes/<id>-DEFAULT` | Callers re-point to the new ARN; re-apply the log group KMS + retention (the sample's `terraform_data.runtime_log_controls` re-runs) |
| Token ledger `sgea-token-usage-<env>` replaced | Usage counters reset (budgets restart) | Avoid; PITR and AWS Backup can restore the old table |
| `create_config_recorder` / `create_guardduty` / `create_securityhub` / `create_inspector` / `manage_account_baseline` flipped | Terraform / CloudFormation deletes the enclave's copy (recorder, detector, hub, account settings) | Keep these values stable; change only together with the landing-zone owner |
| CDK upgrade that changes a construct's logical id | CloudFormation replaces it; `RETAIN` resources (buckets, log groups, ECR, ledger, KMS keys, backup vault) are orphaned and their fixed names collide (`AlreadyExists`) | Reject; report to the SGEA maintainers |
| Conformance pack template changes | The pack's rules are redeployed; results restart | Re-evaluate (section 7); expect transient `INSUFFICIENT_DATA` |
| SCP bundles change the audit-protection exemptions, or a pipeline role changes | Applies by a principal that is no longer exempt fail on the trail, the recorder, `/sgea/*` log groups and the enclave key (`DenyAuditTampering`) | Update `policies.org_policy_exempt_principal_arns` and apply the SCP bundles before the pipeline change |
| `manage_monitoring`, `create_access_analyzer` or `create_unused_access_analyzer` set to false | The alarms, event rules, analyzers (and the CDK drift schedule) are deleted; deleting an analyzer is denied by the audit-protection SCP to non-exempt principals | Record which signals stop (incident response, signal inventory) and the replacement the landing zone provides |
| `create_break_glass_role` set to false | The role `sgea-<env>-break-glass` and its alarm are deleted | Have another emergency path ready first ([access review](access-review.md), section 6) |

## 5. Review gates

| Gate | Pass condition | Owner |
|---|---|---|
| G1 Diff review | Section 3 step 4 done; every changed control decision explained | Platform engineer + reviewer |
| G2 `sgea verify` | Exit 0 | Platform engineer |
| G3 `sgea check` on the real plan / both templates | Exit 0; `UNVERIFIED` items accepted or `--strict` passes | Platform engineer |
| G4 Replacement review | No unplanned replacement or destroy of a stateful resource (section 4) | Platform engineer + ISSO |
| G5 Control changes | ISSO approved new / changed dispositions, exceptions, known findings and SGEA controls | ISSO |
| G6 Prerequisites | New `MANUAL-STEPS.md` section 1 items done (e.g. Lambda quota) | Deployment team |
| G7 Rehearsal | Same upgrade applied over a non-production enclave from the previous export (in-place path not yet validated) | Platform engineer |
| G8 Change record | Change window, rollback plan (section 8), restore point (section 3 step 2), tenant notice | Change manager |

## 6. Apply order

**Terraform** — one root stack (both regions via the `aws.replica` provider; the SCP / RCP layer too when
`deploy_org_policies = true`, which must run from the Organizations management or delegated-administrator account).

1. `terraform apply tfplan` — the plan reviewed at G3 / G4, never a fresh unreviewed one.
2. `terraform output -json enclave` and compare with the previous output.
3. Re-plan and apply each tenant app against the new `enclave` output (and the new `modules/` the tenant's
   `.sgea-modules` link points to).

**CDK** — two stacks; the replica stack must exist first (the primary stack depends on it).

1. `npx cdk deploy SgeaEnclaveLogReplica <same -c sgea:... context>` (replica region).
2. `npx cdk deploy SgeaEnclave <same context>` (primary region). `npx cdk deploy --all` deploys in this order.
3. Do **not** pass `--no-rollback` in production (the sandbox driver uses it for debugging only); keep
   CloudFormation's automatic rollback.
4. Read the `Enclave` output of `SgeaEnclave` and re-apply each tenant app as for Terraform.

## 7. After the apply

1. Re-evaluate the conformance-pack rules (packs keep stale results otherwise; e.g. `dynamodb-in-backup-plan` for up to
   24 h): `aws configservice start-config-rules-evaluation --config-rule-names <rule ...>` (Config console:
   Conformance packs → Re-evaluate). Then confirm each pack with
   `aws configservice describe-conformance-pack-compliance --conformance-pack-name <pack> --filters ComplianceType=NON_COMPLIANT`
   — only known findings and documented exceptions may remain.
2. Run the daily checks in `OPERATIONS.md` (alarms, DLQs, backup jobs) and confirm the token meter heartbeat is fresh
   (otherwise the gateway interceptor fails closed).
3. Run a tenant smoke test: the sample's `examples/sample-agent/scripts/e2e_test.py` in non-production, or the tenant's
   own equivalent (authenticated call, tool call allowed, PII blocked, unauthenticated call rejected).
4. Update the evidence: keep the new `resolved_profile.json`, the `sgea check` output, the plan / change sets and the
   change record; re-collect the as-deployed configuration
   (`python3 tools/collect_evidence.py --profile profiles/<profile>.json --engine terraform|cdk --env <env> --out <your evidence dir>`,
   read-only); record the change in the SSP / POA&M as your process requires.
5. Replace the rollback copy (`build/<profile-id>/`) with the new export only after the change is accepted.

## 7a. Drift detection

Drift is any change to the enclave made outside the IaC. Look for it continuously, not only before an upgrade:

- **CDK.** The EventBridge Scheduler schedule `sgea-<env>-drift-detect` runs CloudFormation drift detection on the SGEA stacks in the primary region once a day (role `sgea-<env>-drift-scheduler`; the log-replica stack is not scheduled, check it by hand with `aws cloudformation detect-stack-drift --stack-name SgeaEnclaveLogReplica --region <replica-region>`). A DRIFTED result reaches `sgea-<env>-security-alarms` through `sgea-<env>-evt-stack-drift` (incident response, playbook 13). Details: `aws cloudformation describe-stack-resource-drifts --stack-name SgeaEnclave --stack-resource-drift-status-filters MODIFIED DELETED`.
- **Terraform.** The enclave creates nothing for this. Schedule a plan in your pipeline (daily is a reasonable default), with credentials that can read the account and the state:

  ```bash
  terraform plan -detailed-exitcode -lock=false -input=false -no-color > drift.txt; rc=$?
  # 0 = no drift, 1 = error, 2 = drift or unapplied changes: alert (for example to sgea-<env>-security-alarms) and review drift.txt
  ```

Handle drift like any other change: find who made it (CloudTrail), then either revert it by re-applying the reviewed IaC or bring it into the profile or inputs through this procedure.

## 8. Rollback

A rollback is itself a change: plan it, check it, review it.

| Situation | Approach |
|---|---|
| Terraform apply failed part-way | Fix forward from the new export, or re-plan from the kept previous export and apply after review. State is in the versioned backend |
| Terraform apply succeeded but the result is wrong | Re-plan from the previous export (`build/<profile-id>/` + the same inputs), `sgea check`, review, apply |
| CDK stack update failed | CloudFormation rolls the stack back automatically (unless `--no-rollback` was used) |
| CDK deploy succeeded but the result is wrong | Re-deploy the previous export's `cdk/` with the same context, replica stack first |
| A stateful resource was replaced | Rollback cannot recover it: restore from AWS Backup (vault `sgea-<env>`), the Aurora final / manual snapshot, or DynamoDB PITR, into a new resource |
| Guardrail version deleted | Re-applying the old definition creates a new version number; tenants re-apply again |
| Key change | Keep the old key enabled until every resource and the token vault are verified on the new one |

After a rollback, repeat section 7.
