<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fda-21-cfr-part-11.json (an overlay) and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — FDA 21 CFR Part 11 / GxP (overlay)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Platform controls sandbox-validated (sample); Part 11 is partly a process framework.** The toolkit configures the platform side (audit trails, retention, access, logging); electronic-signature SOPs and computer system validation (CSV) are owned by the quality/validation team.

## What it is

An overlay that composes on a FedRAMP baseline and lengthens audit-record retention to 7 years, asserts immutable audit-trail and model-invocation logging, and adds the Part 11 control catalog. Add the HIPAA overlay as well when clinical data includes ePHI.

## Who it's for

Organizations running regulated clinical or GxP research where electronic records and electronic signatures fall under FDA 21 CFR Part 11.

## Reference profile

`profiles/fedramp-moderate-part11.commercial.json` (Moderate + Part 11; add `hipaa` to extends for ePHI).

## What this vertical configures (resolved composite)

| Setting | Value |
|---|---|
| Partition | aws |
| Regions | us-east-1, us-east-2, us-west-2 (primary us-east-1) |
| Guardrail tier | standard |
| PII/PHI handling | block / PHI entities False |
| Policy packs | 6 SCP, 2 RCP |
| Log retention | 2555 days |
| HIPAA-eligible-only surface | False |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Moderate baseline), FDA 21 CFR Part 11 (electronic records & signatures) |

## Deployment notes

- **Overlay, not a baseline** — compose on FedRAMP Moderate/High.
- Audit-record retention is set to 2555 days (7 years); confirm against your record-retention SOP.
- **Electronic signatures** (§11.50/§11.70/§11.200) and **CSV** (validation lifecycle) are process controls — the toolkit flags them; the quality/validation team owns the SOPs and the validation package.
- Immutable audit trails: enable object-lock / write-once retention on the audit log store (platform side).
- Add the HIPAA overlay when the clinical records include ePHI.

## Generate the IaC

```bash
python sgea.py resolve --profile profiles/fedramp-moderate-part11.commercial.json
python sgea.py export  --profile profiles/fedramp-moderate-part11.commercial.json --out build/
```
