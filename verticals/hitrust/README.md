<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/hitrust.json (an overlay) and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — HITRUST CSF (overlay)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Sandbox-validated sample overlay — certification labels require assessor/ISSO review.** HITRUST CSF is a certifiable framework; the toolkit configures the platform controls and provides the CSF crosswalk as a starting mapping, not a certification.

## What it is

An overlay that composes on a FedRAMP baseline **and the HIPAA overlay** (HITRUST CSF harmonizes HIPAA with other authorities). It adds the HITRUST CSF v11 control catalog and keeps the PHI-tightened guardrail and HIPAA-eligible-only service posture.

## Who it's for

Healthcare and life-sciences organizations whose business associates, third parties or funders expect HITRUST CSF certification on top of HIPAA.

## Reference profile

`profiles/fedramp-moderate-hitrust.commercial.json` (Moderate + HIPAA + HITRUST).

## What this vertical configures (resolved composite)

| Setting | Value |
|---|---|
| Partition | aws |
| Regions | us-east-1, us-east-2, us-west-2 (primary us-east-1) |
| Guardrail tier | standard |
| PII/PHI handling | block / PHI entities True |
| Policy packs | 6 SCP, 2 RCP |
| Log retention | 365 days |
| HIPAA-eligible-only surface | True |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Moderate baseline), HIPAA Security Rule (45 CFR §164.308–.316), NIST SP 800-66 Rev 2 (HIPAA implementation guidance), HITRUST CSF v11 |

## Deployment notes

- **Overlay, not a baseline** — always compose on FedRAMP Moderate/High; it does not set partition or regions.
- Normally stacked on the HIPAA overlay, since HITRUST CSF incorporates the HIPAA Security Rule.
- HITRUST certification is an external assessor process; the toolkit's CSF control mapping is a starting point for that assessment, not a substitute.
- Inherits the PHI entity set and HIPAA-eligible-only service surface from the HIPAA overlay.

## Generate the IaC

```bash
python sgea.py resolve --profile profiles/fedramp-moderate-hitrust.commercial.json
python sgea.py export  --profile profiles/fedramp-moderate-hitrust.commercial.json --out build/
```
