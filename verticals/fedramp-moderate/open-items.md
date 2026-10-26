<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-moderate.json and are emitted by ../../sgea.py. -->

# FedRAMP Moderate (commercial) — Open Items & Caveats

- IaC is brace/structure-checked only in the toolkit — run `terraform validate` / `cdk synth` and a sandbox apply under the organization's own SCPs before production.
- Confirm per-component AgentCore FedRAMP status against AWS Artifact.
- OpenSearch Serverless remains deferred as a vector store pending FedRAMP confirmation; Aurora PostgreSQL is the first-release default.
