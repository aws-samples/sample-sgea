# ADR 0001 — Wrapper-seam IaC, official modules where they exist

**Status:** Accepted · **Date:** 2026-10-13

## Context

SGEA emits IaC (Terraform and CDK) for the enclave from one resolved control
profile. Two directives shaped this decision:

1. **"Use the official Terraform and CDK modules, not our own."**
2. **"If we use custom modules we could replace them with official modules in
   the future a lot easier."**

These are in tension only if "custom module" means "reinvented resource
logic." They reconcile if our modules are **adapters (seams)**, not
reimplementations.

## What we verified (2026-10-13)

- **CloudFormation covers the resource layer — including GovCloud.** The
  `AWS::BedrockAgentCore::Runtime | RuntimeEndpoint | Gateway | Memory |
  BrowserCustom | CodeInterpreterCustom` and `AWS::Bedrock::Guardrail |
  KnowledgeBase` resource types are registered in **both** `us-east-1` and
  `us-gov-west-1` (live availability check).
- **`awscc` is the official Terraform path for AgentCore.** The
  `hashicorp/awscc` provider (official, HashiCorp-maintained) is generated from
  the CloudFormation registry, so those `AWS::BedrockAgentCore::*` types surface
  as `awscc_bedrockagentcore_*` resources. The mature `hashicorp/aws` provider
  trails on AgentCore; `awscc` does not.
- **CDK L1 == CloudFormation.** `aws-cdk-lib.aws_bedrockagentcore` L1 constructs
  exist because the CFN resources do. The L2s
  (`@aws-cdk/aws-bedrock-agentcore-alpha`, `aws-bedrock-alpha`) are
  **experimental** and may change without notice.
- **Aurora is a first-class, official KB vector store.** Amazon Bedrock
  Knowledge Bases support Amazon Aurora PostgreSQL/pgvector via the RDS Data
  API. So `awscc_bedrock_knowledgebase` with an **RDS storage configuration**
  satisfies the enclave's Aurora-only decision using an official resource.
- **`aws-ia/bedrock` is NOT adopted.** The one official Bedrock Terraform module
  (`aws-ia/bedrock`, 0.0.x) carries a hard dependency on OpenSearch Serverless
  and leans toward S3 Vectors — both excluded by the enclave's vector-store
  decision. Using `awscc_bedrock_knowledgebase` directly avoids that conflict.
- **The governance layer has no official equivalent.** Org SCP/RCP enforcement,
  tenant isolation, the per-user token-control layer, and the log splitter are
  **compositions** of raw resources (`aws_organizations_policy`, Lambda,
  DynamoDB, IAM). No official module publishes them.

## Decision

SGEA emits **thin wrapper modules keyed on the SGEA resolved-config shape**.
Two kinds of seam:

- **Resource-layer seam → pass-through to an official resource/construct.**
  Terraform: `awscc_bedrock_guardrail`, `awscc_bedrock_knowledgebase` (RDS /
  Aurora), `awscc_bedrockagentcore_runtime`, etc. CDK: the `aws_bedrockagentcore`
  L1 constructs. The wrapper only maps resolved-config inputs to the official
  resource — it adds no resource logic.
- **Governance-layer seam → raw official provider resources.** Where nothing
  official exists, the wrapper holds raw `aws_*` / `awscc_*` resources and
  becomes the single place to point at an official module if one ever ships.

**The wrapper interface is the resolved-config shape, never the shape of what is
behind it.** This is the rule that keeps the seam real: callers (the live
stacks) depend only on the SGEA interface, so swapping a wrapper's internals
(raw resources → official module) is a one-file change with no caller edits.

## Consequences

- "Official where it exists" is honored: every Bedrock/AgentCore resource comes
  from an official provider resource (`awscc`) or construct (CDK L1).
- Future migration cost is designed down to **one edit per layer** — change the
  wrapper's internals or its `source`, callers untouched.
- The governance layer stays SGEA-owned because there is nothing official to
  adopt; it is isolated behind its own wrappers so it is the only bespoke code.
- Alpha CDK L2s are avoided in favor of L1 until they stabilize.
- `aws-ia/bedrock` may be revisited if a future version supports Aurora without
  the OpenSearch dependency — it would slot in behind the
  `bedrock-knowledge-base` wrapper with no caller change (the seam's payoff).

## Rejected alternatives

- **Inline raw resources, no modules.** Honors "no own modules" literally but
  scatters the swap across every stack and loses reuse/versioning — strictly
  worse than a thin seam. (Was briefly selected, then reversed on directive 2.)
- **Strict official-only, drop governance from IaC.** Would stop the generator
  standing up the inherited-controls enclave end to end — the governance layer
  is the toolkit's value.
- **`aws-ia/bedrock` for the resource layer.** Rejected for the OpenSearch/S3
  Vectors dependency conflicting with the Aurora-only decision.


## Amendment (2026-10-14) — reuse published modules/constructs inside the seams

Directive: do not reinvent what already exists. Inside each wrapper seam:

- **Terraform** uses the `terraform-aws-modules` collection (community-maintained, the de-facto
  standard; there are no AWS/HashiCorp-official modules for these) at **exact pinned versions**:
  kms 4.2.2, s3-bucket 5.17.0 (+ `//modules/notification`), cloudwatch 5.7.3 (`//modules/log-group`),
  ecr 3.2.0, dynamodb-table 5.5.2, rds-aurora 10.4.1, lambda 8.12.0, vpc 6.7.3
  (`//modules/vpc-endpoints`), network-firewall 2.3.0 (+ `//modules/rule-group`). Raw official
  provider resources remain only where no module exists: Bedrock / AgentCore (`awscc`), CloudTrail,
  Config conformance packs, AWS Backup, GuardDuty / Security Hub, Organizations policies.
- **CDK** uses AWS's official, stable **L2** constructs for the foundation (`kms.Key`, `s3.Bucket`,
  `logs.LogGroup`, `iam.Role`, `cloudtrail.Trail`, `lambda.Function`, `ecr.Repository`,
  `dynamodb.Table`, `rds.DatabaseCluster`, `backup.BackupVault/BackupPlan`, `ec2.FlowLog`). L1 stays
  only where the L2 is alpha or absent (Bedrock / AgentCore, Network Firewall, GuardDuty, Security Hub,
  Config, Organizations, VPC endpoints from ids). Escape hatches are limited to CloudFormation
  properties the L2 does not model (CloudTrail advanced selectors, cross-region replication by ARN,
  EventBridge notifications without the helper Lambda, Lambda VPC config from ids).
- The swap was verified lossless with `sgea check`: identical required-control results on the
  Terraform sandbox plan and the synthesized CloudFormation. `tests/` asserts every registry module
  is pinned to an exact version.
