<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fedramp-high.json and are emitted by ../../sgea.py. -->

# FedRAMP High (GovCloud) — Open Items & Caveats

This vertical is **unverified scaffold**. Before it can be used in production:

1. Confirm Amazon Bedrock + AgentCore availability and FedRAMP High authorization in AWS GovCloud (US) via AWS Artifact.
2. Re-resolve every service in the allow-list against GovCloud service availability.
3. Validate the High control set mapping (NIST 800-53 Rev 5 High) with the ISSO.
4. Rebuild and test the IaC in a GovCloud sandbox under the organization's own SCPs.
5. Remove the `scaffold-unverified` status in `baselines/fedramp-high.json` only after the above.
