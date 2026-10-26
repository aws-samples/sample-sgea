<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-low.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — FedRAMP Low (commercial)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Sandbox-validated sample baseline** (Terraform and CDK). It has fewer control requirements than the Moderate baseline, for low-impact workloads: the same enclave architecture and isolation model, with Low-impact control stringency.

## What it is

A shared Amazon Bedrock + AgentCore enclave in the commercial AWS partition at the FedRAMP Low impact level. The multi-tenant architecture, tenant isolation, and inherited-controls model are identical to Moderate — only the control stringency relaxes (shorter log retention, lighter content-filter strength, the Low control catalog).

## Who it's for

Organizations placing low-impact, non-sensitive workloads in commercial AWS (US East/West) that want the enclave pattern without the full Moderate control weight. Step up to the Moderate profile when the data warrants it.

## Reference profile

`profiles/fedramp-low.commercial.json` (composes this baseline).

## What this vertical configures

| Setting | Value |
|---|---|
| Partition | aws |
| Regions | us-east-1, us-east-2, us-west-2 (primary us-east-1, geo `us`) |
| Guardrail tier | standard |
| Enforced guardrail levels | L1_org, L2_account_baseline, L3_tenant_enforced, gateway_tool_path |
| PII/PHI handling | block / action BLOCK / PHI entities False |
| Content-filter strength | HATE/INSULTS/SEXUAL/VIOLENCE MEDIUM, MISCONDUCT LOW, PROMPT_ATTACK HIGH |
| Policy packs | 5 SCP, 1 RCP |
| Log retention | 90 days |
| Tenant log split / sensitive store | True / True |
| HIPAA-eligible-only surface | False |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Low baseline) |
| Token control | enabled, fail-closed 4h |

## What relaxes vs Moderate

- **Log retention** drops from 365 to **90 days** (still the schema floor).
- **Content filters** step down from HIGH to **MEDIUM** (prompt-attack stays HIGH).
- **Control catalog** is the Low baseline rather than Moderate.
- **Policy packs** drop the resource/network data-perimeter extras (data-perimeter SCP, network-perimeter RCP); region lockdown, Bedrock-surface, inference-profile, guardrail-enforce and tenant-isolation are **kept** — isolation does not relax with impact level.

## Deployment notes

- US geographic inference profiles (`us.*`) only; `global.*` is denied.
- AgentCore has no FIPS endpoints — keep FIPS on for Bedrock, pin AgentCore to the standard endpoint.
- Subnets must be in AgentCore-supported AZ IDs or resource creation fails.
- Multi-tenancy and the inherited-controls model are unchanged from Moderate — this is a stringency relaxation, not an architecture change.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/fedramp-low.commercial.json
python sgea.py export  --profile profiles/fedramp-low.commercial.json --out build/
```
