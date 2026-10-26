<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-high.json and are emitted by ../../sgea.py. -->

# FedRAMP High (GovCloud) — Responsibility & Evidence

## Four-layer shared responsibility

![Four-layer shared responsibility for agentic AI: AWS (inherited cloud service controls), the platform team's enclave (guardrails, logging, isolation, keys, network; operated once and shared by tenants), each application team (its application, data and configuration) and the ISSO / authorizing official (determines compliance). SGEA checks 181 conformance-pack rules and 43 Bedrock / AgentCore controls across 9 framework baselines with 0 open coverage gaps; it evaluates the IaC and does not make the system compliant.](../../docs/diagrams/sgea_01_shared_responsibility.png)

Every SGEA enclave splits responsibility across four layers. The compliance vertical decides which controls sit where and which catalogs the evidence maps to.

| Layer | Owns | In this vertical |
|---|---|---|
| **AWS** | The cloud service controls | Inherited from AWS's FedRAMP/HIPAA authorization (pull from AWS Artifact) |
| **Platform team** | The enclave itself — guardrails, SCPs, logging, isolation, keys, network | Operated under one authorization; the largest inherited layer |
| **Tenant** | Its application, data and configuration | The only layer each application team authorizes |
| **ISSO / AO** | Oversight, acceptance, continuous monitoring | Reviews the evidence package below |

## Control catalogs this vertical maps to

- NIST SP 800-53 Rev 5 (High baseline)

## Responsibility-matrix workbook

CRM profile: `fedramp-high`. The workbook reconciles the AWS layer to AWS's own CRM classifications; do not reproduce AWS's internal responsibility text — pull it from AWS Artifact.

## Continuous monitoring

ConMon evidence scaffold: enabled.

_The generated responsibility summary (AWS CRM classifications per control family) requires the AWS Artifact reports and `tools/build_catalog.py`; it is not part of this distribution._
