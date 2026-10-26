<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/hipaa.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — HIPAA (overlay)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Sandbox-validated sample overlay.** Composed on top of a FedRAMP baseline — it is not a standalone enclave. Responsibility-matrix labels are the toolkit's mapping and **require ISSO review**.

## What it is

A control overlay that tightens a FedRAMP baseline for ePHI: it enables the PHI entity set in guardrails, restricts the production service surface to HIPAA-eligible services only, and adds the HIPAA control catalogs. Partition and regions come from the base it is composed onto.

## Who it's for

Organizations whose tenants handle electronic protected health information (ePHI) — research data, clinical or health records.

## Reference profile

`profiles/fedramp-moderate-hipaa.commercial.json` (Moderate + this overlay).

## What this vertical configures

| Setting | Value |
|---|---|
| Guardrail tier | — |
| PII/PHI handling | block / action BLOCK / PHI entities True |
| HIPAA-eligible-only service surface | True |
| Control catalogs | HIPAA Security Rule (45 CFR §164.308–.316), NIST SP 800-66 Rev 2 (HIPAA implementation guidance) |

## Deployment notes

- **Overlay, not a baseline** — always combine with FedRAMP Moderate or High; it does not set partition or regions itself.
- PHI tenants share the production account, so **every production service in-boundary must be HIPAA-eligible**; the overlay forces `hipaa_eligible_only = true`.
- The organization accepts the AWS Business Associate Addendum (BAA) at project start; the BAA covers the whole account.
- Amazon Bedrock and Amazon Bedrock AgentCore are on the AWS HIPAA-eligible services list; IAM, Budgets, Cost Explorer, CUR, Service Quotas, Artifact and Transit Gateway are not — use those only without ePHI.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/fedramp-moderate-hipaa.commercial.json
python sgea.py export  --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/
```
