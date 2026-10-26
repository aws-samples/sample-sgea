<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-high.json and are emitted by ../../sgea.py. -->

# SGEA Compliance Vertical — FedRAMP High (GovCloud)

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

**Scaffold — NOT yet validated.** Standing this baseline up is its own effort. `sgea.py export` refuses it unless `--allow-unverified` is passed, and then marks the output non-production.

## What it is

The enclave pattern in the AWS GovCloud (US) partition at FedRAMP High. This is not a configuration flip of Moderate — the partition change moves endpoints, ARNs, and service availability, and the High control set is materially stricter.

## Who it's for

Organizations placing high-impact workloads that require AWS GovCloud (US) and the FedRAMP High control set.

## Reference profile

`profiles/fedramp-high.govcloud.json` (marked `scaffold-unverified`).

## What this vertical configures

| Setting | Value |
|---|---|
| Partition | aws-us-gov |
| Regions | us-gov-west-1, us-gov-east-1 (primary us-gov-west-1, geo `us-gov`) |
| Guardrail tier | standard-plus |
| Enforced guardrail levels | L1_org, L2_account_baseline, L3_tenant_enforced, gateway_tool_path |
| PII/PHI handling | block / action BLOCK / PHI entities False |
| Log retention | 1095 days |
| Tenant log split / sensitive store | True / True |
| Control catalogs | NIST SP 800-53 Rev 5 (High baseline) |

## Deployment notes

- **Partition change is a build axis, not a toggle:** GovCloud endpoints/ARNs differ throughout.
- **Verify service availability in GovCloud** — confirm every service in the allow-list is available AND authorized at High in GovCloud before use. Amazon Bedrock / AgentCore GovCloud availability and FedRAMP High status must be confirmed against AWS Artifact.
- Inference profiles switch to the `us-gov` geography.
- Longer log retention (1095 days) and stricter guardrail/content-filter posture than Moderate.

## Generate the IaC

```bash
# from the toolkit root
python sgea.py resolve --profile profiles/fedramp-high.govcloud.json
python sgea.py export  --profile profiles/fedramp-high.govcloud.json --out build/
```

> This vertical is a scaffold. `export` will refuse it unless you pass `--allow-unverified`, and the output is marked non-production until the baseline is validated against GovCloud.
