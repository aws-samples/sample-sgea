# Testing SGEA in your own sandbox account

This page shows how to deploy an SGEA enclave and the sample tenant agent into **your own** AWS account, run the
7-check end-to-end test, collect the as-deployed configuration evidence, and tear everything down again. It uses the
tooling SGEA's own validation runs use:

| Tool | What it does |
|---|---|
| `examples/run_sandbox_test.sh` | One profile, one engine: sandbox network, enclave (gated on `sgea check`), sample agent, e2e test. Leaves everything running. |
| `tools/sandbox_teardown.py` | Collects evidence, then tears down the sample agent, the enclave and (optionally) the sandbox network. |
| `tools/sandbox_matrix.sh` | Runs deploy, e2e and teardown for several profiles x engines, one after another. |
| `tools/collect_evidence.py` | Read-only as-deployed configuration evidence for a live deployment. |
| `tools/bootstrap_sdk.sh` | Installs a current boto3 (with `bedrock-agentcore-control`) into a private directory the tools use first. |

> **Billable, and built to resist deletion.** These tools create real resources (VPC interface endpoints, Aurora
> Serverless v2, KMS keys, CloudTrail, AWS Config, GuardDuty / Security Hub where absent, Network Firewall for IL4 /
> IL5). The enclave's controls (Object Lock, deletion protection, Backup vault lock) are what the teardown removes, so
> run them **only in a dedicated, non-production account** that holds nothing else. Never point them at an account
> with production data or a shared landing zone.

The sandbox run follows the lower row of this diagram: `sgea check` gates the deploy, then the e2e test, evidence and teardown.

![How SGEA works: baselines and a profile go to sgea resolve, which produces the resolved config (single source of truth); derived.py feeds terraform_emitter.py, cdk_emitter.py, manual_steps.py and operations.py, which write build/<profile-id>/ (terraform/, cdk/, resolved_profile.json, MANUAL-STEPS.md, OPERATIONS.md); sgea check gates the sandbox deploy, the 7-check e2e test on a sample tenant agent, the read-only evidence report and the ordered teardown.](diagrams/sgea_02_pipeline.png)

---

## 1. Prerequisites

### Account

- A **dedicated sandbox account** with no other workloads. The tools use fixed resource names (`sgea-<env>-*`, env
  `sbx` by default), so only **one enclave and one run at a time** per account.
- Credentials with administrator-level permissions in that account (the enclave creates IAM roles, KMS key policies,
  AWS Config, CloudTrail, GuardDuty and Security Hub settings). The sandbox run does **not** deploy the Organizations
  SCP/RCP layer (`deploy_org_policies = false`), so it needs no management-account access.
- Commercial profiles only (`profiles/*.commercial.json`); their primary region is `us-east-1` and the log store
  replicates to the next allowed region (`us-east-2`). GovCloud profiles need a GovCloud account and are not covered by
  the sandbox tooling's validation.

### Credentials argument

Every tool takes the same `<credentials>` value (first argument of `run_sandbox_test.sh` and `sandbox_matrix.sh`,
`--account` of `sandbox_teardown.py` and `sandbox_plan.py`):

| Value | Meaning |
|---|---|
| an AWS CLI profile name, e.g. `my-sandbox-profile` | Exported as `AWS_PROFILE`; static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` in the environment are dropped so they cannot override it |
| `env` | The ambient credential chain as-is (environment variables, instance role, ...) |

The region is always the profile's resolved primary region. Prefer a profile whose credentials refresh themselves
(for example IAM Identity Center or a `credential_process`): a full run takes about an hour, and static session
credentials that expire mid-apply leave a half-built enclave. Check before every run:

```bash
aws sts get-caller-identity --profile my-sandbox-profile --query Account --output text   # must print your sandbox account id
```

### Quotas and service access (from `MANUAL-STEPS.md`)

Export the profile first and work through section 1 of its `MANUAL-STEPS.md`:

```bash
sgea export --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/
less build/fedramp-moderate-hipaa-commercial/MANUAL-STEPS.md
```

- **Lambda concurrent-executions quota** (`L-B99A9384`) in the primary region: the FedRAMP / DoD packs need at least
  **1,100** (the default is 1,000). `MANUAL-STEPS.md` prints the exact `aws service-quotas` request commands. An
  increase can take days. `run_sandbox_test.sh` checks the quota before it creates anything and stops with exit
  code 3 if it is too low.
- **Bedrock model access.** The sample agent's default model is an Anthropic model; in a fresh account, Anthropic
  models may need a one-time model-access use-case submission in the Bedrock console.
- **HIPAA / HITRUST profiles:** the sandbox holds no PHI, but `MANUAL-STEPS.md` lists the BAA step for real deployments.

### CDK bootstrap

For `--cdk` runs, `run_sandbox_test.sh` runs `npx cdk bootstrap aws://<account>/<region>` itself for the primary and
the replica region. If your credentials cannot create the `CDKToolkit` stack, bootstrap both regions beforehand with
an identity that can (`MANUAL-STEPS.md`, "CDK bootstrap").

### Local tools

- Python 3.9+ with the SGEA CLI installed (`INSTALL.md`), Terraform ≥ 1.11, AWS CLI v2.
- Node.js ≥ 18 with npm (CDK runs; `npm ci` runs per export).
- **Finch or Docker** to build the sample agent's `linux/arm64` image (`examples/sample-agent/scripts/build_push.sh`
  uses `finch`; set `FINCH=docker` to use Docker). On an x86 host your engine needs arm64 emulation.
- A boto3 / botocore that includes `bedrock-agentcore-control` (the teardown resets the AgentCore token vault; the
  evidence collector reads AgentCore). Install one into a private directory the tools put first on `sys.path`:

  ```bash
  tools/bootstrap_sdk.sh            # default /tmp/sgea-boto; or: tools/bootstrap_sdk.sh <dir> and export SGEA_BOTO=<dir>
  ```

  Without it the tools fall back to the interpreter's own boto3; the teardown and the evidence collector exit with a
  clear message, **before deleting anything**, if that one lacks the service. `/tmp` does not survive a reboot.

---

## 2. Run one profile

```bash
examples/run_sandbox_test.sh my-sandbox-profile profiles/fedramp-moderate-hipaa.commercial.json --yes         # Terraform
examples/run_sandbox_test.sh my-sandbox-profile profiles/fedramp-moderate-hipaa.commercial.json --yes --cdk   # CloudFormation (CDK)
```

`--yes` is required (the script refuses to create billable resources without it). The profile defaults to
`profiles/fedramp-moderate-hipaa.commercial.json`. Set `SGEA_EXPECT_ACCOUNT_ID=123456789012` to make the script
refuse (exit 6) unless the credentials belong to that account; set `SGEA_ENV` to change the environment name
(default `sbx`).

The six steps:

1. **Sandbox network** — `examples/sandbox-network` (a private, internet-less fixture VPC). One shared network for
   every run, state in `.sandbox/_network/`.
2. **Enclave** — `sgea export`, the quota preflight, then a Terraform plan (or `cdk synth`), the **`sgea check`
   gate** on that plan or the synthesized templates (exit 5 on any required `FAIL`), then apply (or
   `cdk deploy --all`). On the first run the script records whether the account already has GuardDuty, Security Hub
   and an AWS Config recorder, and creates only the missing ones; that decision is stored in
   `.sandbox/<profile-id>[-cdk]/sandbox.auto.tfvars.json` and reused by later runs.
3. **Agent image** — builds the arm64 sample agent and pushes it to the enclave ECR repository (immutable tag).
4. **Sample tenant app** — `examples/sample-agent/infra` (test Cognito IdP, gateway tool, AgentCore runtime).
5. **End-to-end test** — `examples/sample-agent/scripts/e2e_test.py`, 7 checks: authenticated invocation answered
   through the guardrail; gateway tool call allowed; PII prompt blocked; contextual PII anonymized, not blocked; token
   meter credits the caller; over-budget tool calls denied; unauthenticated call rejected. It prints `N/7 passed`.
6. **Done** — everything stays up for inspection; the script prints the teardown command.

State per run: `.sandbox/<profile-id>/` (Terraform) or `.sandbox/<profile-id>-cdk/` (CDK). Do not delete it before the
teardown: the teardown uses it.

| Exit code | Meaning |
|---|---|
| 2 | Missing `--yes`, or the credentials could not be resolved |
| 3 | Lambda concurrency quota preflight failed (nothing created yet) |
| 5 | `sgea check` gate failed on the plan / templates (enclave not applied) |
| 6 | Credentials are not for `SGEA_EXPECT_ACCOUNT_ID` |

---

## 3. Tear down

```bash
python3 tools/sandbox_teardown.py --account my-sandbox-profile --account-id 123456789012 \
    --profile profiles/fedramp-moderate-hipaa.commercial.json [--cdk] [--network] [--no-evidence] [--env sbx]
```

- It refuses to run unless the credentials' account equals `--account-id`, then **asks you to type the account id**.
  There is no `--yes`.
- `--cdk` must match how the enclave was deployed. `--env` defaults to `$SGEA_ENV` or `sbx`.
- `--network` also destroys the shared sandbox network (normally kept for the next run).
- `--no-evidence` skips step 0. Use it after a failed deploy, and when re-running a teardown that stopped part-way
  (otherwise it records "evidence" from a half-destroyed enclave over a good report).

### Order, and why

| Step | What | Why this order |
|---|---|---|
| 0 | As-deployed evidence (`tools/collect_evidence.py`), only if a deployment exists | The configuration can only be read while it exists |
| 1 | Destroy the sample tenant app (retried once after 60 s) | Tenant resources depend on the enclave's gateway, keys and network |
| 1b | **Reset the AgentCore token vault** to the service-managed key | The vault is account-wide and encrypted with the enclave CMK. Switching it later must decrypt with the current key: if the CMK is scheduled for deletion first, no later enclave can deploy in that account |
| 1c | **Stop the enclave's AWS Config recorder** (`sgea-<env>`) | AWS Config refuses to delete a delivery channel while its recorder records (the stack delete would not stabilize). A recorder the account already had is not touched |
| 2 | Lift deletion protections: Aurora, the DynamoDB token ledger, Network Firewall, Backup vault lock and access policy (recovery points deleted); earlier sandbox final snapshots deleted | Each protection would make the destroy fail, by design |
| 3 | Empty the `sgea-<env>-*` buckets in both regions (Object Lock GOVERNANCE bypass), delete the ECR images | Non-empty buckets and repositories cannot be deleted |
| 4 | Destroy the enclave (Terraform, emptying the buckets again and retrying once; or `cdk destroy`, then delete the resources the CDK app retains under the env prefix), then the network with `--network`, then Aurora's exported log group | Logging keeps writing until the trail, Config and log delivery are gone; a leftover log group blocks the next deploy |

The teardown tolerates resources that are already gone, so a re-run continues where the previous one stopped. It
ends with `teardown complete`. With `--network`, AgentCore can leave network interfaces in the runtime subnets for a
while after the runtime is deleted; if the network destroy fails with `DependencyViolation`, wait and re-run the
teardown with `--network`.

---

## 4. Run the matrix

```bash
tools/sandbox_matrix.sh my-sandbox-profile 123456789012 --yes                                                    # every profiles/*.commercial.json x {terraform, cdk}
tools/sandbox_matrix.sh my-sandbox-profile 123456789012 --yes profiles/fedramp-low.commercial.json:cdk           # one pair
tools/sandbox_matrix.sh my-sandbox-profile 123456789012 --yes profiles/fedramp-low.commercial.json:terraform \
                                                             profiles/fedramp-moderate-hipaa.commercial.json
```

For each profile x engine it runs `run_sandbox_test.sh` with `SGEA_EXPECT_ACCOUNT_ID` set to the account id, then
the teardown (the account id is piped to the confirmation prompt; `--no-evidence` when the deploy failed), and
appends one result row to `docs/SANDBOX-MATRIX.md` (the file is created on the first run).

- The account id must be 12 digits. A run whose credentials belong to another account stops the matrix (exit 6).
- If a teardown fails, the matrix **stops** (exit 4): the fixed resource names would collide with the next run. Read
  the teardown log, fix the cause, re-run `tools/sandbox_teardown.py ... --no-evidence` by hand with the same profile
  and engine flag, then restart the matrix with only the remaining pairs.
- Each run takes about an hour; all commercial profiles x both engines take most of a day.
- Logs: `/tmp/sgea-matrix/<profile-id>-<engine>.log` and `...-teardown.log`, overwritten by a re-run of the same pair.
  They contain account ids and ARNs: do not publish them.
- In zsh, do not write `"$P:terraform"` (`:t` is a zsh modifier); write `"${P}:terraform"` or the literal path.
- Do not edit the scripts or the emitters while a matrix runs: every run re-exports, and bash reads scripts
  incrementally.

---

## 5. Evidence

The teardown collects evidence automatically (step 0). To collect it on its own against a live deployment
(read-only `describe` / `get` / `list` calls; credentials from the environment):

```bash
AWS_PROFILE=my-sandbox-profile python3 tools/collect_evidence.py \
    --profile profiles/fedramp-moderate-hipaa.commercial.json --engine terraform [--env sbx] [--out <dir>]
```

It writes `<profile-id>-<engine>.md` and `.json` to `--out` (default `docs/evidence/`): for every enclave resource the
observed setting, the value the resolved profile expects, whether it meets it, and the framework controls it
evidences, plus the live conformance-pack compliance. The account id and IAM unique ids are redacted; no secrets,
prompts or log contents are read. `python3 -I tools/evidence_index.py` writes an index (`docs/evidence/README.md`)
over the reports in `docs/evidence/`, the known findings and the documented exceptions.

KMS keys of earlier, torn-down runs still pending deletion show up in the reports as `sandbox-artifact`; that is
expected.

---

## 6. Cost

- The enclave's fixed monthly floor at list prices is in the profile's `MANUAL-STEPS.md` ("Running cost estimate");
  usage (endpoint data, Aurora ACUs, AWS Config evaluations, CloudTrail data events, log ingestion, model calls) comes
  on top. The largest fixed items are the VPC interface endpoints (about 22, in 2 AZs) and Aurora Serverless v2.
- A single run is billed for the hours it is up; tear down as soon as you have looked at the results. A full matrix is
  many hours of enclave time.
- GuardDuty and Security Hub, if the run created them, bill per account usage.

---

## 7. Cleanup after the teardown

What a complete teardown intentionally leaves behind:

| Leftover | What to do |
|---|---|
| **KMS keys pending deletion** (30-day window; descriptions start with `SGEA`) | Let the window expire. Do not cancel a deletion unless you need the key back. If a later deploy fails creating the token-vault CMK setting because the vault still names a pending-deletion key: cancel the deletion, enable the key, set the vault to the service-managed key, re-schedule the deletion (`docs/operations/key-and-secret-management.md`, section 3) |
| Aurora final snapshot (`sgea-<env>-vector-final`; CDK: `sgeaenclave-snapshot-auroracluster*`) | Kept on purpose; the next teardown deletes it. When you are finished with the account, find it with `aws rds describe-db-cluster-snapshots --snapshot-type manual` and delete it with `aws rds delete-db-cluster-snapshot` |
| Shared sandbox network (unless `--network`) | Re-run the teardown with `--network` when you are done |
| `CDKToolkit` stacks and their staging buckets (CDK runs) | Normal CDK bootstrap resources; remove them only if nothing else in the account uses CDK |
| GuardDuty / Security Hub / Config recorder the run created | Disable them when you retire the sandbox account |
| Local state: `.sandbox/`, `build/`, `/tmp/sgea-matrix/`, `/tmp/sgea-boto` | Delete after the teardown has finished (not before) |

List the keys still pending deletion (read-only):

```bash
for k in $(aws kms list-keys --profile my-sandbox-profile --region us-east-1 --query 'Keys[].KeyId' --output text); do
  aws kms describe-key --profile my-sandbox-profile --region us-east-1 --key-id "$k" \
      --query 'KeyMetadata.[KeyId,KeyState,DeletionDate,Description]' --output text
done | grep PendingDeletion
```

Repeat for the replica region (`us-east-2` for the commercial profiles).

---

## 8. Before production

A sandbox pass is not an authorization. Before a real deployment, repeat the apply under your organization's own SCPs
(the sandbox does not deploy the SCP/RCP layer), work through the whole `MANUAL-STEPS.md`, and have your ISSO review
the SGEA-authored controls and rule dispositions. Day-2 operation: the generated `OPERATIONS.md` and
[`docs/operations/`](operations/).
