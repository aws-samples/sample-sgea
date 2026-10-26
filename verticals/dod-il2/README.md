<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/dod-il2.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — DoD IL2 (commercial East/West)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Scaffold — NOT yet validated.** Standing this baseline up is its own effort. `sgea.py export` refuses it unless `--allow-unverified` is passed, and then marks the output non-production.

## What it is

The enclave pattern at DoD SRG Impact Level 2 (IL2), for public and non-controlled unclassified DoD information, in the **commercial** partition, US East/West regions (`us-east-1`, `us-east-2`, `us-west-1`, `us-west-2` — the AWS Services-in-Scope 'DoD CSP SRG IL2 (East/West)' boundary). IL2 is FedRAMP Moderate (Class C) plus the DoD SRG IL2 catalog; there is no partition change. Every enclave service, including Bedrock AgentCore, is IL2-authorized in East/West.

## Who it's for

DoD mission owners (and third-party organizations operating under a DoD sponsor) placing CUI workloads that must meet the DoD Cloud Computing SRG at IL2 and run in AWS commercial East/West.

## Reference profile

`profiles/dod-il2.commercial.json` (marked `scaffold-unverified`).

## What this vertical configures

| Setting | Value |
|---|---|
| Partition | aws-us-gov (commercial East/West) |
| Regions | us-gov-west-1, us-gov-east-1 (primary us-gov-west-1, geo `us-gov`) |
| Guardrail tier | standard-plus |
| PII handling | block / action BLOCK / PHI entities False |
| Log retention | 1095 days (3 years) |
| HIPAA-eligible-only surface | False (add the HIPAA overlay if ePHI is in scope) |
| Vector store | aurora-postgresql |
| Control catalogs | NIST SP 800-53 Rev 5 (Moderate baseline) + DoD SRG IL2 |
| Token control | enabled, fail-closed 4h |

## Deployment notes

- **Partition change is a build axis, not a toggle:** commercial East/West endpoints/ARNs differ throughout; the IaC provider wiring targets `aws-us-gov`.
- **Verify service availability AND DoD PA scope in commercial East/West** — confirm every service in the allow-list is available in commercial East/West and in scope under the AWS DoD Provisional Authorization at IL2 before use (AWS Artifact).
- Inference profiles use the `us-gov` geography.
- IL2 carries DoD-specific **personnel and access requirements** (e.g. US-person restrictions) that are process controls — document them in the vertical, they are not expressible in IaC.
- Longer retention (1095 days) and the stricter `standard-plus` guardrail posture, matching the FedRAMP High scaffold.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/dod-il2.commercial.json
python sgea.py export  --profile profiles/dod-il2.commercial.json --out build/ --allow-unverified
```

> This vertical is a scaffold. `export` refuses it unless you pass `--allow-unverified`, and the output is marked non-production until the baseline is validated against commercial East/West, the DoD SRG, and the AWS DoD Provisional Authorization scope.
