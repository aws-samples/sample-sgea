# SGEA examples — deploy and test in a sandbox

| Path | What it is |
|---|---|
| `sandbox-network/` | Test fixture: private, internet-less VPC (terraform-aws-modules/vpc + security-group) shaped like the enclave expects. Not part of the enclave. |
| `sample-agent/` | A tenant app on the enclave: AgentCore Runtime agent + Gateway tool + test IdP. See its README. |
| `run_sandbox_test.sh` | One-shot deploy + end-to-end test into ONE sandbox account. |

## Run it

```bash
# prerequisites: terraform >= 1.11, python3 + boto3, finch (or FINCH=docker), AWS credentials for a sandbox account
# <credentials>: an AWS CLI profile name, or `env` for the ambient credential chain
examples/run_sandbox_test.sh my-sandbox-profile profiles/fedramp-moderate-hipaa.commercial.json --yes
```

The driver:

1. applies `sandbox-network`,
2. exports the profile, writes sandbox settings (`deploy_org_policies = false` — a single sandbox account is
   not an Organizations management account; GuardDuty / Security Hub / Config recorder created only if the
   account does not already have them), **plans, runs `sgea check` on the plan (gate)**, then applies,
3. builds the arm64 agent image and pushes it to the enclave ECR (immutable tag),
4. deploys the sample tenant,
5. runs `sample-agent/scripts/e2e_test.py`.

State lives in `.sandbox/<profile-id>/`. Everything is left running for inspection.

**Network note for real enclaves:** S3 is reached through the gateway endpoint at S3's public ranges, so
security groups of anything pulling from ECR (agent runtimes, Lambdas) must allow HTTPS egress to the
`com.amazonaws.<region>.s3` managed prefix list — the sandbox fixture does this.

**Cost:** ~22 interface endpoints × 2 AZs, Aurora Serverless v2 (2 × 0.5 ACU), KMS keys, CloudTrail data events,
Config. Tear down when done.

## Tear down

```bash
python3 tools/sandbox_teardown.py --account my-sandbox-profile --account-id 123456789012 \
    --profile profiles/fedramp-moderate-hipaa.commercial.json
```

The enclave resists deletion by design (Object Lock, deletion protection, vault lock). The teardown lifts those
in a sandbox only (it checks the account id and asks you to type it), empties the log buckets with governance
bypass, then destroys tenant → enclave → network. KMS keys enter a 30-day deletion window; Aurora leaves a final
snapshot.
