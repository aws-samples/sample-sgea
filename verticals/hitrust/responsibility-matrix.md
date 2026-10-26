<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/hitrust.json (an overlay) and are emitted by ../../sgea.py. -->

# HITRUST CSF (overlay) — Responsibility & Evidence

## Four-layer shared responsibility

![Four-layer shared responsibility for agentic AI: AWS (inherited cloud service controls), the platform team's enclave (guardrails, logging, isolation, keys, network; operated once and shared by tenants), each application team (its application, data and configuration) and the ISSO / authorizing official (determines compliance). SGEA checks 181 conformance-pack rules and 43 Bedrock / AgentCore controls across 9 framework baselines with 0 open coverage gaps; it evaluates the IaC and does not make the system compliant.](../../docs/diagrams/sgea_01_shared_responsibility.png)

| Layer | Owns | In this vertical |
|---|---|---|
| **AWS** | Cloud service controls | Inherited from AWS's FedRAMP/HIPAA authorization (AWS Artifact) |
| **Platform team** | The enclave — guardrails, SCPs, logging, isolation, keys, network | Operated under one authorization; the largest inherited layer |
| **Tenant** | Its application, data and configuration | The only layer each application team authorizes |
| **ISSO / AO / Assessor** | Oversight, acceptance, certification, continuous monitoring | Reviews the evidence below |

## Control catalogs this vertical maps to

- NIST SP 800-53 Rev 5 (Moderate baseline)
- HIPAA Security Rule (45 CFR §164.308–.316)
- NIST SP 800-66 Rev 2 (HIPAA implementation guidance)
- HITRUST CSF v11

## Responsibility-matrix workbook

CRM profile: `hitrust`. These mappings are the toolkit's starting point and require review by the ISSO and (for HITRUST) the external assessor.

_The generated responsibility summary (AWS CRM classifications per control family) requires the AWS Artifact reports and `tools/build_catalog.py`; it is not part of this distribution._
