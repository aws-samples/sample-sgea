<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/dod-il5.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — DoD IL5 (GovCloud)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Scaffold — NOT yet validated.** Standing this baseline up is its own effort. `sgea.py export` refuses it unless `--allow-unverified` is passed, and then marks the output non-production.

## What it is

The enclave pattern at DoD SRG Impact Level 5 (IL5), for Controlled Unclassified Information (CUI) for DoD mission owners, in the AWS GovCloud (US) partition. IL5 builds on FedRAMP High (Class D) and adds DoD-specific control and personnel requirements. This is not a configuration flip of a commercial baseline — the partition change moves endpoints, ARNs, and service availability, and the DoD SRG adds requirements FedRAMP Moderate does not.

## Who it's for

DoD mission owners (and third-party organizations operating under a DoD sponsor) placing CUI workloads that must meet the DoD Cloud Computing SRG at IL5 and run in AWS GovCloud.

## Reference profile

`profiles/dod-il5.govcloud.json` (marked `scaffold-unverified`).

## What this vertical configures

| Setting | Value |
|---|---|
| Partition | aws-us-gov (GovCloud) |
| Regions | us-gov-west-1, us-gov-east-1 (primary us-gov-west-1, geo `us-gov`) |
| Guardrail tier | standard-plus |
| PII handling | block / action BLOCK / PHI entities False |
| Log retention | 1095 days (3 years) |
| HIPAA-eligible-only surface | False (add the HIPAA overlay if ePHI is in scope) |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Moderate baseline) + DoD SRG IL5 |
| Token control | enabled, fail-closed 4h |

## Deployment notes

- **Partition change is a build axis, not a toggle:** GovCloud endpoints/ARNs differ throughout; the IaC provider wiring targets `aws-us-gov`.
- **Verify service availability AND DoD PA scope in GovCloud** — confirm every service in the allow-list is available in GovCloud and in scope under the AWS DoD Provisional Authorization at IL5 before use (AWS Artifact).
- Inference profiles use the `us-gov` geography.
- IL5 carries DoD-specific **personnel and access requirements** (e.g. US-person restrictions) that are process controls — document them in the vertical, they are not expressible in IaC.
- Longer retention (1095 days) and the stricter `standard-plus` guardrail posture, matching the FedRAMP High scaffold.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/dod-il5.govcloud.json
python sgea.py export  --profile profiles/dod-il5.govcloud.json --out build/ --allow-unverified
```

> This vertical is a scaffold. `export` refuses it unless you pass `--allow-unverified`, and the output is marked non-production until the baseline is validated against GovCloud, the DoD SRG, and the AWS DoD Provisional Authorization scope.
