# Deployment team: manual steps outside the IaC

`sgea export` writes the exact list for a profile to `<out>/<profile-id>/MANUAL-STEPS.md` (numbers and
regions filled in from the resolved config and the composed packs). This page is the general reference.

## Before the first deploy (AWS requests / other accounts)

| Step | Needed for | How | Lead time |
|---|---|---|---|
| **Lambda concurrent-executions quota** (`L-B99A9384`) >= enclave functions x `ConcurrencyLimitLow` + 100 (= **1,100** for the 500 the FedRAMP Low / Moderate / High, DoD IL2 / IL5 packs set; default quota is 1,000) | `lambda-concurrency-check` | Service Quotas increase request in the enclave account and primary region (may become an AWS Support case). Command in `MANUAL-STEPS.md`. Size for tenant functions too. | Hours to days |
| AWS GovCloud (US) account | FedRAMP High, DoD IL4 / IL5 profiles | GovCloud sign-up linked to the commercial payer | Days |
| AWS Business Associate Addendum | HIPAA / HITRUST profiles | AWS Artifact → Agreements (account or organization) | Same day |
| Organizations membership; SCP/RCP deployment from the management / delegated-admin account | All profiles (`account-part-of-organizations`, org policy layer) | `deploy_org_policies = true` with `org_id`, `org_target_ids`, perimeter inputs — run from the management account; test on a sandbox OU | Change window |
| DoD SCCA: BCAP connection, routing through the VDSS firewall endpoints, TCCM | DoD IL4 / IL5 | DISA / mission owner | Weeks |
| CDK bootstrap (primary + replica region) | CDK path | `npx cdk bootstrap aws://<account>/<region>` | Minutes |

## Landing-zone overlap

Where Control Tower / LZA or an org delegated administrator already owns a setting, turn the enclave's copy off:
`create_config_recorder`, `create_guardduty`, `create_securityhub`, `create_inspector`, `manage_account_baseline`
(CDK: `-c sgea:createConfigRecorder=false` etc.).

## Customer-owned prerequisites and process controls

Generated per profile in `MANUAL-STEPS.md` from `sources/inferred/rule-dispositions.yaml` (`customer-prerequisite`
and `process` dispositions): root MFA, IAM Identity Center instead of IAM users, private VPC subnets without IGW
routes, security groups without open ingress, risk assessment / incident-response exercise evidence.

## After the first deploy

Subscribe the security team to `sgea-<env>-security-alarms`; confirm the conformance packs in AWS Config; ISSO review
of the SGEA-inferred controls and rule dispositions.
