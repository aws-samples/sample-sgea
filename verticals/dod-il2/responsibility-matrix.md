<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/dod-il2.json and are emitted by ../../sgea.py. -->

# DoD IL2 (commercial East/West) — Responsibility & Evidence

## Four-layer shared responsibility

![Four-layer shared responsibility for agentic AI: AWS (inherited cloud service controls), the platform team's enclave (guardrails, logging, isolation, keys, network; operated once and shared by tenants), each application team (its application, data and configuration) and the ISSO / authorizing official (determines compliance). SGEA checks 181 conformance-pack rules and 43 Bedrock / AgentCore controls across 9 framework baselines with 0 open coverage gaps; it evaluates the IaC and does not make the system compliant.](../../docs/diagrams/sgea_01_shared_responsibility.png)

| Layer | Owns | In this vertical |
|---|---|---|
| **AWS** | The cloud service controls | Inherited from the AWS DoD Provisional Authorization at IL2 (pull from AWS Artifact) |
| **Platform team** | The enclave itself — guardrails, SCPs, logging, isolation, keys, network | Operated under one authorization; the largest inherited layer |
| **Tenant** | Its application, data and configuration | The only layer each application team authorizes |
| **ISSO / AO (DoD)** | Oversight, acceptance, continuous monitoring | Reviews the evidence package below; a DoD AO issues the ATO |

## Control catalogs this vertical maps to

- NIST SP 800-53 Rev 5 (Moderate baseline)
- DoD SRG IL2

## Responsibility-matrix workbook

CRM profile: `dod-il2`. The workbook reconciles the AWS layer to AWS's DoD PA scope; do not reproduce AWS's internal responsibility text — pull it from AWS Artifact. DoD-specific personnel and access controls (US-person restrictions, background investigations) are process controls owned by the mission owner and are tracked outside the IaC.

## Continuous monitoring

ConMon evidence scaffold: enabled. DoD ConMon expectations differ from the civilian FedRAMP cadence — confirm the reporting cadence and artifacts with the DoD AO.

_The generated responsibility summary (AWS CRM classifications per control family) requires the AWS Artifact reports and `tools/build_catalog.py`; it is not part of this distribution._
