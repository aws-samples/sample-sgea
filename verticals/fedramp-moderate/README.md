<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-moderate.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — FedRAMP Moderate (commercial)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Reference sample baseline** — sandbox-validated end to end on both engines (Terraform and CDK).

## What it is

A shared Amazon Bedrock + AgentCore enclave in the commercial AWS partition, configured for the FedRAMP Moderate baseline (AWS “Class C” regions). The enclave itself is not FedRAMP-authorized; it supports your authorization. Tenants inherit the full control set rather than each pursuing their own authorization.

## Who it's for

Organizations placing moderate-impact (the majority of FedCiv) workloads in commercial AWS (US East/West). The default starting point for most adopters.

## Reference profile

`profiles/fedramp-moderate-hipaa.commercial.json` (composes this baseline; drop the HIPAA overlay for Moderate-only).

## What this vertical configures

| Setting | Value |
|---|---|
| Partition | aws |
| Regions | us-east-1, us-east-2, us-west-2 (primary us-east-1, geo `us`) |
| Guardrail tier | standard |
| Enforced guardrail levels | L1_org, L2_account_baseline, L3_tenant_enforced, gateway_tool_path |
| PII/PHI handling | block / action BLOCK / PHI entities False |
| Policy packs | 6 SCP, 2 RCP |
| Log retention | 365 days |
| Tenant log split / sensitive store | True / True |
| HIPAA-eligible-only service surface | False |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Moderate baseline) |
| Token control | enabled=True, fail-closed 4h |

## Deployment notes

- US geographic inference profiles (`us.*`) only; `global.*` is denied.
- AgentCore has no FIPS endpoints — keep FIPS on for Bedrock, pin AgentCore to the standard endpoint.
- Subnets must be in AgentCore-supported AZ IDs or resource creation fails.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/fedramp-moderate-hipaa.commercial.json
python sgea.py export  --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/
```
