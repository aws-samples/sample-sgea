<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/hipaa.json and are emitted by ../../sgea.py. -->

# HIPAA (overlay) — Responsibility & Evidence

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

- HIPAA Security Rule (45 CFR §164.308–.316)
- NIST SP 800-66 Rev 2 (HIPAA implementation guidance)

## Responsibility-matrix workbook

CRM profile: `hipaa`. The HIPAA Security Rule workbook (§164.308–.316) carries responsibility labels that are the toolkit's mapping and **must be reviewed by the ISSO** before use.

## Continuous monitoring

ConMon evidence scaffold: enabled.

_The generated responsibility summary (AWS CRM classifications per control family) requires the AWS Artifact reports and `tools/build_catalog.py`; it is not part of this distribution._
