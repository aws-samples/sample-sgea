<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/sgea-logo-dark.svg"><img src="docs/assets/sgea-logo.svg" alt="SGEA — Secure GenAI Enclave Accelerator" width="420"></picture></p>

# Secure GenAI Enclave Accelerator (SGEA) — Toolkit

SGEA generates a governed, compliance-configured home for an organization's AI agents on **Amazon Bedrock** and
**Amazon Bedrock AgentCore**. A deployment team picks a control profile — **FedRAMP Low / Moderate / High, DoD IL2 /
IL4 / IL5, HIPAA, HITRUST, FDA 21 CFR Part 11**, or a stack of them — and SGEA emits matching infrastructure-as-code
in **Terraform and CloudFormation (via AWS CDK, TypeScript)**, checks that IaC against every requirement of the chosen
frameworks, lists the manual steps outside the IaC, and (in a sandbox) tests the deployed result end to end and
records the as-deployed configuration as evidence.

SGEA is customer-agnostic: a profile never contains customer data, and a reference adopter never changes the IaC.

![Four-layer shared responsibility for agentic AI: AWS (inherited cloud service controls), the platform team's enclave (guardrails, logging, isolation, keys, network; operated once and shared by tenants), each application team (its application, data and configuration) and the ISSO / authorizing official (determines compliance). SGEA checks 181 conformance-pack rules and 43 Bedrock / AgentCore controls across 9 framework baselines with 0 open coverage gaps; it evaluates the IaC and does not make the system compliant.](docs/diagrams/sgea_01_shared_responsibility.png)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

---

## Contents

1. [What you get](#what-you-get)
2. [How it works](#how-it-works)
3. [Install](#install)
4. [Usage](#usage) — list / resolve / export / verify / check, manual steps, deploy, sandbox test, evidence
5. [Frameworks and validation status](#frameworks-and-validation-status)
6. [What the enclave deploys](#what-the-enclave-deploys)
7. [Control coverage](#control-coverage)
8. [Repository layout](#repository-layout)
9. [Documentation map](#documentation-map) — framework docs, operations runbooks, testing
10. [Maintaining the source data](#maintaining-the-source-data)
11. [Known open findings and limitations](#known-open-findings-and-limitations)
12. [Security](#security)
13. [License](#license)

---

## What you get

For one profile, `sgea export` writes `build/<profile-id>/`:

| Output | What it is |
|---|---|
| `terraform/` | Root stack + 16 wrapper modules built on pinned `terraform-aws-modules` and the official `aws` / `awscc` providers. `terraform init && terraform apply`. |
| `cdk/` | AWS CDK (TypeScript) app synthesizing two CloudFormation stacks (`SgeaEnclave`, `SgeaEnclaveLogReplica`) from official L2 constructs (L1 where the L2 is alpha or absent). `npm ci && npx cdk deploy --all`. |
| `resolved_profile.json` | The single source of truth both engines were generated from (audit copy of every control decision). |
| `MANUAL-STEPS.md` | Everything the deployment team must do outside the IaC for this profile: AWS requests (e.g. the Lambda concurrency quota), other-account steps (Organizations SCPs, BAA, GovCloud), landing-zone overlaps, customer-owned prerequisites, process controls, **known open findings**, a **running-cost estimate** (fixed monthly floor from current list prices), post-deploy steps. |
| `OPERATIONS.md` | Day-2 runbook for this profile: daily / weekly / monthly / quarterly checks (alarms the enclave actually emits, pack compliance, backups, concurrency headroom, cost), restore tests, and a **continuous-monitoring evidence calendar** for the composed frameworks. Links to the operations docs below. |

Around that, the toolkit provides:

- **`sgea check`** — evaluates a Terraform plan or the synthesized CloudFormation against every required control of the
  composed frameworks (AWS Config conformance-pack rules + SGEA's Bedrock / AgentCore controls). `verify` and the
  sandbox driver gate on it.
- **Framework catalogs** (`catalog/`) built from AWS-published sources: Config conformance packs, AWS docs control
  mappings, AWS Services in Scope, regional availability, Bedrock model authorization.
- **Control coverage register** — every Config rule of every pack has a check or a recorded disposition; the catalog
  build fails otherwise (`docs/CONTROL-COVERAGE.md`).
- **Sample tenant agent** (`examples/sample-agent`) — an AgentCore Runtime agent that uses the enclave's guardrail,
  gateway tool path, memory and token budgets, with a 7-check end-to-end test.
- **Sandbox tooling** — one-command deploy + e2e test + teardown in a dedicated sandbox account, a profile x engine
  matrix runner, and a read-only **as-deployed configuration evidence** collector ([`docs/TESTING.md`](docs/TESTING.md)).
- **Framework documents** (`docs/frameworks/`) — one generated page per framework: conformance packs, profiles,
  validation status, coverage counts, customer responsibilities, exceptions, known findings, evidence links.
- **Operations documentation** (`docs/operations/`) — incident response, key and secret management, change and
  upgrade, tenant onboarding, decommissioning, access review and break-glass.

## How it works

**One profile → one resolved config → two thin emitters → wrapper-seam IaC → checked against the framework catalogs.**

![How SGEA works: baselines and a profile go to sgea resolve, which produces the resolved config (single source of truth); derived.py feeds terraform_emitter.py, cdk_emitter.py, manual_steps.py and operations.py, which write build/<profile-id>/ (terraform/, cdk/, resolved_profile.json, MANUAL-STEPS.md, OPERATIONS.md); sgea check gates the sandbox deploy, the 7-check e2e test on a sample tenant agent, the read-only evidence report and the ordered teardown.](docs/diagrams/sgea_02_pipeline.png)

The same flow as text:

```
baselines/*.json        composable control fragments (fedramp-moderate, hipaa, dod-il5, ...)
   │  profiles/*.json   names a composition + overrides + emit targets (extends[], later wins)
   ▼
sgea resolve            validates schema, partition / region boundary, Services-in-Scope authorization,
   │                    HIPAA eligibility, Bedrock model authorization
   ▼
RESOLVED CONFIG ──► emitters/derived.py  (shared derivations: retention, backup, endpoints, policy bundles,
   │                │                     account baseline, pack parameters)
   │                ├─► terraform_emitter.py ─► terraform/
   │                ├─► cdk_emitter.py       ─► cdk/
   │                ├─► manual_steps.py      ─► MANUAL-STEPS.md
   │                └─► operations.py        ─► OPERATIONS.md
   ▼
catalog/<baseline>.json ─► sgea check (plan / CFN) ─► sandbox: deploy ─► e2e test ─► evidence ─► teardown
```

Control decisions live **only** in the resolved config; the emitters translate it and never re-decide, which keeps the
Terraform and CDK outputs in lock-step. Each layer sits behind a thin "seam" module / construct so an official module
can replace it later as a one-file change (`docs/adr/0001`).

## Install

```bash
pipx install .                         # from the toolkit root; or: python -m pip install .
python -m pip install -e ".[dev]"      # development: + pytest, jsonschema
python -m pip install ".[catalog]"     # + openpyxl — only to rebuild catalogs from the AWS Artifact workbooks
```

Requirements: Python ≥ 3.9 (PyYAML is installed with the CLI). To verify or deploy the IaC: Terraform ≥ 1.11 and
Node.js ≥ 18 with npm (the CDK toolchain is installed per export by `npm ci`). Sandbox tooling additionally: AWS CLI v2,
a boto3 that includes `bedrock-agentcore-control`, Finch or Docker (arm64 image build), and credentials for a dedicated
sandbox account (an AWS CLI profile, or the ambient credential chain).

The CLI finds `baselines/`, `profiles/`, `catalog/` and `sources/` at the **toolkit root** — `$SGEA_ROOT`, else the
nearest parent directory containing them. Run it inside a checkout or set `SGEA_ROOT`. Details: `INSTALL.md`.

## Usage

### 1. Pick and inspect a profile

```bash
sgea list                                                                  # baselines (+ scaffold status), profiles
sgea resolve --profile profiles/fedramp-moderate-hipaa.commercial.json     # resolved config; fails on any violation
```

Compose your own profile by extending baselines (`profiles/_schema.json` is the contract), e.g.
`"extends": ["fedramp-moderate", "hipaa"]` with region and environment overrides.

### 2. Export the IaC

```bash
sgea export --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/
#   -> build/fedramp-moderate-hipaa-commercial/{terraform/, cdk/, resolved_profile.json, MANUAL-STEPS.md}
sgea export --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/ --emit terraform   # one engine
```

Scaffold baselines (FedRAMP High, DoD IL2 / IL4 / IL5) need `--allow-unverified`; the output is then marked
non-production and authorization gaps become warnings.

### 3. Verify (credential-free)

```bash
sgea verify --out build/fedramp-moderate-hipaa-commercial
```

Runs `terraform fmt -check` and `terraform validate`, `cdk synth` (with placeholder VPC / subnet inputs) and
`sgea check --cfn` on the synthesized templates. Exit 0 = everything passes (all 8 shipped profiles do).

### 4. Check a real plan or template against the frameworks

```bash
# Terraform: plan in the target account (read-only), then check
cd build/<id>/terraform && terraform init && terraform plan -out tfplan && terraform show -json tfplan > plan.json && cd -
sgea check --out build/<id> --plan build/<id>/terraform/plan.json

# CDK: synth with your environment inputs, then check both templates
(cd build/<id>/cdk && npm ci && npx cdk synth -c sgea:vpcId=vpc-... -c sgea:agentSubnetIds=subnet-a,subnet-b ...)
sgea check --out build/<id> --cfn build/<id>/cdk/cdk.out/SgeaEnclave.template.json \
                            --cfn build/<id>/cdk/cdk.out/SgeaEnclaveLogReplica.template.json
```

| Status | Meaning |
|---|---|
| `PASS` / `FAIL` | The planned / synthesized value meets / violates the requirement |
| `GAP` | An enclave-owned rule not implemented yet (none today) — counts as a failure |
| `NOT-EMITTED` | The resource needs an input not supplied (e.g. the per-tenant runtime) |
| `N/A-APP` / `N/A` | Created by tenant apps / not applicable to this profile or input set |
| `UNVERIFIED` | Value only known after apply (e.g. an ARN created in the same apply) — never counted as PASS; `--strict` fails on it |
| `accounted` | Rule with a recorded disposition: tenant / not-in-enclave / customer-prerequisite / process / runtime-only |

Exit code 5 on any required `FAIL` or `GAP` (`--allow-gaps` tolerates `NOT-EMITTED`); `-v` also lists passing controls.

**Environment inputs** (Terraform variables / CDK `-c sgea:<name>`): VPC id; endpoint, agent and Aurora subnets and
security groups; route tables; org id, target ids and perimeter (for the SCP/RCP layer); optional JWT issuer for the
gateway and runtimes; and switches for what the landing zone already owns — `create_config_recorder`,
`create_guardduty`, `create_securityhub`, `create_inspector`, `manage_account_baseline`, `deploy_org_policies`. See the
exported `terraform/variables.tf` and `cdk/lib/constructs/context.ts`.

### 5. Do the manual steps, then deploy

Work through `MANUAL-STEPS.md` **before the first deploy** — section 1 needs AWS requests or other accounts (e.g. a
Lambda concurrent-executions quota ≥ 1,100 for the FedRAMP / DoD packs, the HIPAA BAA, SCPs from the management
account). Then:

```bash
cd build/<id>/terraform && terraform init && terraform apply                       # Terraform
cd build/<id>/cdk && npm ci && npx cdk bootstrap aws://<acct>/<primary> aws://<acct>/<replica> \
                  && npx cdk deploy --all -c sgea:vpcId=... ...                    # CloudFormation (CDK)
```

After the deploy: subscribe the security team to `sgea-<env>-security-alarms`, re-evaluate the conformance-pack rules,
and review the pack results (post-deploy section of `MANUAL-STEPS.md`). General reference:
`docs/DEPLOYMENT-PREREQUISITES.md`. From then on, run the enclave with `OPERATIONS.md` and the
[operations documents](#documentation-map); onboard app teams with
[`docs/operations/tenant-onboarding.md`](docs/operations/tenant-onboarding.md).

![Application-team responsibility matrix: inherited from the enclave (baseline guardrail, identity framework and gateway JWT authorizer, tenant-isolation SCPs / RCPs and data perimeter, model allow-list, enclave CMK, network endpoints, logging and conformance packs, token budgets, backup and detective controls, the control baseline and evidence) versus owned by the application team (agent code, its data, OIDC app client, scoped execution role, container image, tool Lambdas, gateway tool registration, runtime via the SGEA wrapper, tenant and profile tags, its full requirement scope and ATO).](docs/diagrams/sgea_04_app_responsibility.png)

*Tag keys are case-sensitive: use exactly `sgea:tenant` and `sgea:profile` (the tenant-isolation SCP compares `aws:PrincipalTag/sgea:tenant` with the resource tag).*

### 6. Sandbox: deploy, end-to-end test, evidence, teardown

Use a **dedicated, non-production AWS account**. `<credentials>` (the first argument / `--account`) is an AWS CLI
profile name, or `env` to use the ambient credential chain. The teardown (and every matrix run) refuses to act
unless the credentials' account equals the account id you pass. Full walkthrough, prerequisites and cleanup: [`docs/TESTING.md`](docs/TESTING.md).

```bash
# network + enclave (gated on sgea check) + sample tenant agent, then the 7-check e2e test
examples/run_sandbox_test.sh my-sandbox-profile profiles/fedramp-moderate-hipaa.commercial.json --yes        # Terraform
examples/run_sandbox_test.sh my-sandbox-profile profiles/fedramp-moderate-hipaa.commercial.json --yes --cdk  # CloudFormation

# once: a boto3 with bedrock-agentcore-control in /tmp/sgea-boto (used first by teardown and evidence)
tools/bootstrap_sdk.sh

# as-deployed evidence (read-only) + teardown; asks you to type the account id
python3 tools/sandbox_teardown.py \
    --account my-sandbox-profile --account-id 123456789012 \
    --profile profiles/fedramp-moderate-hipaa.commercial.json [--cdk] [--network]

# every commercial profile x {terraform, cdk}, one at a time: deploy, e2e, teardown
tools/sandbox_matrix.sh my-sandbox-profile 123456789012 --yes [profiles/x.json[:terraform|:cdk] ...]

# evidence on its own, against any live sandbox deployment (read-only; credentials from the environment)
AWS_PROFILE=my-sandbox-profile python3 tools/collect_evidence.py --profile profiles/x.json --engine terraform|cdk [--out <dir>]
```

The **e2e test** (`examples/sample-agent/scripts/e2e_test.py`) asserts: an authenticated (JWT) invocation is answered
through the enclave guardrail · the agent's gateway tool call is **allowed** by the tool-path policy · a PII prompt is
blocked · contextual PII (e.g. an address) is masked, not blocked · the token meter credits the caller's usage · an
over-budget caller's tool calls are denied · an unauthenticated call is rejected (401).

The **teardown** collects evidence first (by default to `docs/evidence/<profile>-<engine>.{md,json}`), then destroys the tenant,
lifts deletion protections, empties the stores, resets the account-wide AgentCore token vault, and destroys the
enclave; the shared sandbox network is kept unless `--network`. It refuses to run unless the credentials' account is
`--account-id`. Sandbox only.

## Frameworks and validation status

| Profile | Baselines composed | Partition | Validation |
|---|---|---|---|
| `fedramp-low.commercial` | FedRAMP Low | commercial | **Sandbox-validated** — e2e 7/7 on Terraform and CDK, evidence |
| `fedramp-moderate-hipaa.commercial` | FedRAMP Moderate + HIPAA | commercial | **Sandbox-validated** — 7/7 both engines, evidence |
| `fedramp-moderate-hitrust.commercial` | FedRAMP Moderate + HIPAA + HITRUST | commercial | **Sandbox-validated** — 7/7 both engines, evidence |
| `fedramp-moderate-part11.commercial` | FedRAMP Moderate + FDA 21 CFR Part 11 | commercial | **Sandbox-validated** — 7/7 both engines, evidence |
| `dod-il2.commercial` | FedRAMP Moderate + DoD IL2 | commercial | **Sandbox-validated** — 7/7 both engines, evidence (baseline still flagged scaffold) |
| `fedramp-high.govcloud` | FedRAMP High | GovCloud | Scaffold — `sgea verify` passes; not deployed (needs a GovCloud account) |
| `dod-il4.govcloud` | DoD IL4 (+ SCCA) | GovCloud | Scaffold — `verify` passes; not deployed; **AgentCore not IL4-authorized** |
| `dod-il5.govcloud` | DoD IL5 (+ SCCA) | GovCloud | Scaffold — `verify` passes; not deployed; **AgentCore not IL5-authorized** |

Per-framework detail (packs, coverage, customer responsibilities, exceptions, known findings, evidence):

| Framework | Document |
|---|---|
| FedRAMP Low | [`docs/frameworks/fedramp-low.md`](docs/frameworks/fedramp-low.md) |
| FedRAMP Moderate | [`docs/frameworks/fedramp-moderate.md`](docs/frameworks/fedramp-moderate.md) |
| FedRAMP High | [`docs/frameworks/fedramp-high.md`](docs/frameworks/fedramp-high.md) |
| HIPAA Security Rule | [`docs/frameworks/hipaa.md`](docs/frameworks/hipaa.md) |
| HITRUST CSF | [`docs/frameworks/hitrust.md`](docs/frameworks/hitrust.md) |
| FDA 21 CFR Part 11 | [`docs/frameworks/fda-21-cfr-part-11.md`](docs/frameworks/fda-21-cfr-part-11.md) |
| DoD IL2 | [`docs/frameworks/dod-il2.md`](docs/frameworks/dod-il2.md) |
| DoD IL4 | [`docs/frameworks/dod-il4.md`](docs/frameworks/dod-il4.md) |
| DoD IL5 | [`docs/frameworks/dod-il5.md`](docs/frameworks/dod-il5.md) |

Index: [`docs/frameworks/README.md`](docs/frameworks/README.md). To repeat the sandbox validation in your own
account: [`docs/TESTING.md`](docs/TESTING.md).

**Regions and models.** FedRAMP Class C / DoD IL2 = US East/West (`us-east-1/2`, `us-west-1/2`); Class D / IL4 / IL5 =
GovCloud (`us-gov-west-1/east-1`). `resolve` fails a region outside the framework boundary or a primary region missing
an allowed service. Only Bedrock models AWS lists as authorized for every composed baseline are allowed (model
allow-list SCP, exact model IDs). The log store replicates to the next allowed region.

## What the enclave deploys

Both engines emit the same resources (Terraform module → CDK construct of the same name):

![Inside the enclave boundary: organization governance (org-guardrail: up to 4 SCPs and 4 RCPs) around tenant apps whose every request passes JWT authentication, the baseline guardrail and the default-deny gateway tool path; inside the boundary the AgentCore platform and runtime, Bedrock guardrails, token control, the Aurora vector store, encryption and network, logging, detective controls, and backup and account baseline. DoD IL4 / IL5 add the SCCA layer.](docs/diagrams/sgea_03_architecture.png)

| Area | Resources and settings |
|---|---|
| Encryption (`enclave-kms`) | Enclave CMK: annual rotation, 30-day deletion window, key policy scoped to the account and the AWS services that use it |
| Logging (`enclave-logging`) | CloudTrail (multi-region, log validation, CMK, CloudWatch delivery, Bedrock / AgentCore / S3 data events); log store (S3: CMK, versioning, Object Lock, TLS-only, Block Public Access, access logging, EventBridge notifications, `s3:ObjectRemoved:*` to a CMK-encrypted SNS topic, cross-region replica); AWS Config delivery bucket; CloudWatch log groups (CMK, retention = max(baseline, pack minimum)); Bedrock model-invocation logging; security-alarm SNS topic (CMK) |
| Guardrails (`bedrock-guardrail`) | Bedrock guardrail from the profile (content filters, PII/PHI entities — hard identifiers BLOCK, contextual entities ANONYMIZE — denied topics, tier), immutable version, account-enforced guardrail (every user message guarded; system prompt where tagged) |
| AgentCore (`agentcore-platform`, `agentcore-runtime`) | Gateway (JWT or IAM auth, CMK, Cedar policy engine in ENFORCE mode — or the SGEA REQUEST interceptor where the engine is unavailable, e.g. GovCloud), memory (CMK, event expiry), token-vault CMK, ECR (immutable tags, scan on push, CMK, lifecycle); runtime wrapper for tenants (VPC-only, JWT authorizer, idle timeout, header allow-list, VPC-endpoint-restricted resource policy) |
| Token control (`token-control`) | Usage ledger (DynamoDB: CMK, PITR, deletion protection); meter Lambda (invocation-log subscription, 15-minute heartbeat, first heartbeat at deploy); the gateway interceptor denies tool calls past per-user daily / per-team monthly budgets and fails closed |
| Network (`enclave-network`) | Interface endpoints for every allowed service (private DNS, only in AZs the service supports), S3 and DynamoDB gateway endpoints, VPC flow logs (CMK) |
| Vector store (`enclave-aurora`) | Aurora PostgreSQL Serverless v2: CMK, IAM auth, Data API, TLS-only, deletion protection, multi-AZ, RDS-managed rotating admin secret on the CMK, CMK log group |
| Backup (`enclave-backup`) | Vault (CMK, vault lock, deny-deletion access policy), daily plan with the pack retention, one selection covering Aurora, the token ledger and the log / config stores |
| Detective (`config-conformance`, `security-services`) | AWS Config recorder + delivery, one AWS conformance pack per composed baseline (with SGEA parameter overlays), GuardDuty, Security Hub (NIST 800-53 Rev 5), Amazon Inspector where a pack requires it |
| Account baseline (`account-baseline`) | EBS encryption by default (CMK), EBS snapshot public-sharing block, account S3 Block Public Access, IAM password policy (pack parameters), closed VPC default security group |
| Monitoring (`enclave-monitoring`) | EventBridge routing of GuardDuty, Security Hub, Inspector, AWS Config compliance, AWS Backup, secret-rotation and Access Analyzer events to the CMK-encrypted alarm topic; CloudTrail metric-filter alarms (trail, Config, KMS, IAM, bucket-policy, network and Organizations changes, root use, console sign-in without MFA, failed sign-ins, unauthorized API calls); Bedrock throttle / server-error / invocation-log-delivery, guardrail-intervention and gateway error / throttle alarms; AWS Budgets (opt-in amount) and Cost Anomaly Detection (opt-in), commercial partition only; IAM Access Analyzer; CloudWatch Transaction Search (X-Ray creates `aws/spans`; CMK and retention are a post-deploy step); optional MFA-only break-glass role with an alarm on every use; daily CloudFormation drift detection (CDK) |
| Governance (`org-guardrail`) | SCP/RCP library bundled into ≤ 4 SCPs + ≤ 4 RCPs: region and service allow-lists, model allow-list, guardrail enforcement, data perimeter, identity and network perimeter, audit protection (deny stopping or deleting the trail, the Config recorder, GuardDuty, Security Hub, Access Analyzer and `/sgea/*` log groups, and disabling, deleting or re-policying keys tagged `sgea:profile`, except for the deployment, break-glass and listed exempt roles) (deployed from the management account) |
| DoD SCCA (`dod-scca`, IL4 / IL5) | VDSS (AWS Network Firewall, default drop, egress allow-list) and VDMS logging |
| Function hygiene | Enclave Lambdas in the VPC with KMS-encrypted dead-letter queues, pack-derived reserved concurrency, X-Ray and CMK-encrypted environment; **no inline IAM policies** anywhere (a CDK aspect converts them) |
| Knowledge base (`bedrock-knowledge-base`) | Per-app wrapper on the Aurora vector store, emitted when its inputs are supplied |

## Control coverage

Every AWS Config rule in every conformance pack a profile composes — 181 distinct rules across the 9 baselines — is
accounted for: `sgea check` evaluates it on the Terraform plan **and** the CDK template, or it carries one recorded
disposition with a reason (`tenant`, `not-in-enclave`, `customer-prerequisite`, `process`, `runtime-only`) in
`sources/inferred/rule-dispositions.yaml`. The catalog build fails on a rule with neither. Enclave resources AWS Config
reports NON_COMPLIANT by design are listed there as documented exceptions, with the reason.

| Framework | Pack rules | Checked by `sgea check` | Open gaps |
|---|---:|---:|---:|
| FedRAMP Low / Moderate / High | 117 / 129 / 145 | 49 / 54 / 69 | 0 |
| HIPAA / HITRUST / FDA Part 11 | 130 / 130 / 129 | 55 / 52 / 57 | 0 |
| DoD IL2 / IL4 / IL5 | 130 / 151 / 163 | 53 / 61 / 72 | 0 |

The other rules concern services the enclave neither deploys nor allows, the customer's landing zone / identity / VPC,
manual processes, or results only observable at runtime — each with its reason in `docs/CONTROL-COVERAGE.md`. SGEA also
checks 43 Bedrock / AgentCore controls of its own (`sources/inferred/service-controls.yaml`).

The published catalogs do not carry the AWS Artifact-derived responsibility-matrix rows (FedRAMP / DoD CRM); download
the AWS Artifact reports yourself and rebuild to add them ([Maintaining the source data](#maintaining-the-source-data)).

## Repository layout

| Path | Contents |
|---|---|
| `sgea.py` | CLI: `list`, `resolve`, `export`, `verify`, `check` |
| `baselines/` | Composable framework fragments (9): guardrails, logging, retention, policies, services, evidence packs |
| `profiles/` | Shipped profiles (8) and `_schema.json` (the resolved-profile contract) |
| `emitters/` | `terraform_emitter.py`, `cdk_emitter.py` + `cdk_app/` (TypeScript constructs and aspects), `derived.py` (shared derivations), `policy_library.py` (SCP/RCP), `guardrail_map.py`, `manual_steps.py`, `operations.py`, `lambda/` (gateway interceptor, token meter) |
| `catalog/` | **Generated** per-baseline framework catalogs (without AWS Artifact-derived content), plus `_services-in-scope.json`, `_regions.json` |
| `sources/` | Pinned sources SGEA may redistribute — `conformance-packs/`, `nist-oscal/`, `provider-schema/` (validation slice) — and `inferred/` (SGEA-authored: service controls, rule plan checks, dispositions + exceptions, known findings, pack-parameter overlays, Bedrock model IDs). The AWS documentation pages and reports the catalogs were built from are referenced by URL in each catalog's `sources`, not redistributed |
| `tools/` | `build_catalog.py`, `snapshot_schema.py`, `sandbox_plan.py`, `sandbox_teardown.py`, `sandbox_matrix.sh`, `bootstrap_sdk.sh`, `collect_evidence.py`, `evidence_index.py`, `framework_docs.py` |
| `examples/` | `sandbox-network/` (fixture VPC), `sample-agent/` (`app/` agent container, `tool/` gateway Lambda, `infra/` tenant Terraform, `scripts/` build + e2e), `run_sandbox_test.sh` |
| `tests/` | Resolver, emitter, policy-library, checker, coverage, manual-steps, operations and framework-doc tests (`pytest -q`) |
| `docs/` | `CONTROL-COVERAGE.md` (generated), `frameworks/` (generated, one page per framework), `operations/` (customer runbooks), `TESTING.md` (testing in your own sandbox account), `DEPLOYMENT-PREREQUISITES.md`, `adr/` |
| `verticals/` | Per-vertical notes and generated responsibility matrices |
| `.github/workflows/` | CI (GitHub Actions) |
| `build/` | Exports (generated, git-ignored) |

## Documentation map

**Per deployment (generated by `sgea export` into `build/<id>/`)**

| Document | Use it for |
|---|---|
| `MANUAL-STEPS.md` | Before and right after the first deploy: AWS requests, other-account steps, prerequisites, process controls, known findings, cost estimate |
| `OPERATIONS.md` | Running the enclave: recurring checks, restore tests, continuous-monitoring evidence calendar |

**Frameworks** — [`docs/frameworks/`](docs/frameworks/README.md), one page per framework (table in
[Frameworks and validation status](#frameworks-and-validation-status)); rule-by-rule detail in
[`docs/CONTROL-COVERAGE.md`](docs/CONTROL-COVERAGE.md).

**Operations (customer)** — [`docs/operations/`](docs/operations/)

| Document | Covers |
|---|---|
| [`incident-response.md`](docs/operations/incident-response.md) | Signal inventory and playbooks per signal the enclave emits (guardrail / PII spikes, token budget, interceptor denials, CloudTrail / Config delivery, log-store deletions, GuardDuty, tenant credential compromise, audit / security-configuration and network changes, root and sign-in alarms, break-glass use, Security Hub / Inspector / Access Analyzer findings, Config compliance and stack drift, backup / rotation failures, Bedrock / gateway health, budget and cost anomalies); escalation template; post-incident review |
| [`key-and-secret-management.md`](docs/operations/key-and-secret-management.md) | Enclave CMKs and key-policy statements, rotation, cancelling a scheduled deletion, token-vault key dependency, Aurora admin secret, JWT / Cognito keys, periodic review |
| [`change-and-upgrade.md`](docs/operations/change-and-upgrade.md) | Upgrading SGEA or the conformance packs: re-export, diff, verify, check, apply order, disruptive changes, SCP exemptions for Terraform pipelines, drift detection, rollback, re-evaluation |
| [`tenant-requirements.md`](docs/operations/tenant-requirements.md) | Application-team contract: numbered requirements (TR-01–TR-25) with how each is verified, the enclave interface, tracing, and compiled code for Python, Node.js, .NET and Java |
| [`tenant-onboarding.md`](docs/operations/tenant-onboarding.md) | What an app team must do to deploy into the enclave, with a checklist |
| [`decommissioning.md`](docs/operations/decommissioning.md) | Teardown order, Object Lock / key deletion windows, record retention, sign-off |
| [`access-review.md`](docs/operations/access-review.md) | Quarterly review of roles, users, key and resource policies, IAM Access Analyzer findings; break-glass procedure (optional SGEA role or your own) |

Before the first deploy: [`docs/DEPLOYMENT-PREREQUISITES.md`](docs/DEPLOYMENT-PREREQUISITES.md).

**Diagrams** — [`docs/diagrams/`](docs/diagrams/): shared responsibility (`sgea_01`), how SGEA works (`sgea_02`), what the enclave deploys (`sgea_03`), application-team responsibility (`sgea_04`).

**Testing** — [`docs/TESTING.md`](docs/TESTING.md): deploy, end-to-end test, evidence and teardown in your own sandbox
account.

Architecture decisions: [`docs/adr/`](docs/adr/).

## Maintaining the source data

The repository ships the **built** catalogs (`catalog/`), so `resolve`, `export`, `verify` and `check` need nothing
else. Rebuild them only to pick up new AWS sources or to change SGEA-authored content:

```bash
python -I tools/build_catalog.py      # rebuild catalog/ and docs/CONTROL-COVERAGE.md (validates coverage)
python3 -I tools/framework_docs.py    # regenerate docs/frameworks/ (a test fails if they are stale)
python -I tools/snapshot_schema.py schema.json build/<id>/terraform/.terraform.lock.hcl   # refresh the provider-schema slice
pytest -q
```

- **Inputs not in this repository.** A rebuild needs the AWS-published pages listed in each catalog's `sources`
  (`pack_url`, `control_mapping_url`) and the other AWS pages it reads (Services in Scope, regional availability),
  downloaded into `sources/`. Some baselines (FedRAMP / DoD responsibility matrices, compliance guides) also need
  AWS Artifact reports, which you download yourself (AWS Artifact; requires an AWS account; NDA). Do not commit or
  redistribute them.
- A new pack rule: add a Terraform + CFN mapping in `sources/inferred/config-rule-plan-checks.json`, or a disposition in
  `rule-dispositions.yaml` (the build names the rule).
- A by-design NON_COMPLIANT result: `exceptions:` in `rule-dispositions.yaml`.
- A rule SGEA cannot fix yet: `sources/inferred/known-findings.yaml`; it flows into every affected profile's
  `MANUAL-STEPS.md`.
- List prices for the cost estimate are constants at the top of `emitters/manual_steps.py` (dated); refresh them from
  the AWS Price List API when quoting.
- CI (GitHub Actions, `.github/workflows/ci.yml`): unit tests, then export + `sgea verify` for every profile
  (credential-free).


## Known open findings and limitations

- **Known open findings** — not fixed in this release; customer actions are in each affected `MANUAL-STEPS.md`:
  - **SGEA-KF-02** `lambda-concurrency-check` for tenant functions — the packs' sample range requires 500–1000 reserved
    concurrent executions per function.
- **Fixed in this release:** SGEA-KF-01 `s3-event-notifications-enabled` — the log stores now notify a CMK-encrypted
  SNS topic; verified live on HITRUST, both engines (2026-10-21).
- **The monitoring layer is new in this release**: deployed and torn down cleanly on HITRUST with both engines, e2e 7/7 (2026-10-27); alarm and event delivery to the topic were not exercised, and the audit-protection SCP was not applied (management account) (`enclave-monitoring`, `docs/adr/0002-enclave-monitoring.md`; runbooks in `docs/operations/`):
  - No subscriptions are created on the SNS topics; subscribe your security team to `sgea-<env>-security-alarms` after deploy.
  - Terraform has no fixed deployment role: list your pipeline role in `policies.org_policy_exempt_principal_arns` before the SCP bundles are applied, or applies that change the trail, the Config recorder, `/sgea/*` log groups or the enclave key are denied.
  - The audit-protection SCP exemption matches role names (`sgea-*-break-glass`, `cdk-hnb659fds-cfn-exec-role-*`) across accounts, so a principal that can create IAM roles could create a matching role and bypass the denies; restrict `iam:CreateRole` in your landing zone until exact, account-scoped ARNs replace the patterns.
  - Terraform does not reset the account-wide AgentCore token vault on destroy (the provider's delete is a no-op); switch it to the service-managed key before `terraform destroy` (`docs/operations/decommissioning.md`). CDK resets it on stack deletion.
- **GovCloud profiles are not deployment-validated** (no GovCloud account in the validation sandbox).
- **AgentCore is not authorized at DoD IL4 / IL5** (AWS Services in Scope: "Independent Assessment"); those profiles
  stay scaffold-only until AWS completes the assessment.
- **SGEA-authored content requires ISSO review**: the Bedrock / AgentCore controls and the rule dispositions are mapped
  to AWS's topic / control mappings and analog Config rules, but are not AWS-published.
- Terraform plans of a fresh account show ARN-valued settings as `UNVERIFIED` (known only after apply); the CDK check
  checks them structurally and AWS Config evaluates them live.
- The SCP/RCP layer must be deployed from the Organizations management (or delegated) account and tested on a sandbox
  OU first; the sandbox validation does not deploy it.
- HITRUST and DoD IL4 have no AWS conformance pack; NIST 800-53 Rev 5 (and CMMC 2.0 L2 for IL2 / IL4) stand in. AWS's
  HIPAA topic mapping covers 19 of 51 topics.
- CloudFormation exposes no customer-managed KMS option for the Network Firewall configuration (Terraform does).
- The CDK app is TypeScript only.
- Not fetchable by the toolkit: FedRAMP High / DoD SRG CRM from GovCloud Artifact, the HIPAA BAA, the HITRUST Shared
  Responsibility Matrix.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information on reporting security issues.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE).
