<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-low.json and are emitted by ../../sgea.py. -->

# FedRAMP Low (commercial) — Open Items & Caveats

- IaC is brace/structure-checked only in the toolkit — run `terraform validate` / `cdk synth` and a sandbox apply under the organization's own SCPs before production.
- Confirm per-component AgentCore FedRAMP status against AWS Artifact.
- Confirm the Low impact level is the right fit — if the workload touches sensitive data, step up to the Moderate profile rather than relaxing controls.
- The 90-day log retention is the schema floor; confirm it meets the organization's own record-retention policy, which may require longer.
- OpenSearch Serverless remains deferred as a vector store pending FedRAMP confirmation; Aurora PostgreSQL is the first-release default.
