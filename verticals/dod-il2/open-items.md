<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/dod-il2.json and are emitted by ../../sgea.py. -->

# DoD IL2 (commercial East/West) — Open Items & Caveats

This vertical is **unverified scaffold**. Before it can be used in production:

1. Confirm the DoD mission owner accepts the AWS DoD IL2 Provisional Authorization scope (AWS Artifact) for every service in the allow-list.
2. Validate the control mapping (NIST SP 800-53 Rev 5 Moderate + DoD SRG IL2) with the DoD AO.
3. Rebuild and test the IaC in a commercial sandbox under the mission owner's own SCPs.
4. Remove the `scaffold-unverified` status in `baselines/dod-il2.json` only after the above.

Other notes:
- Add the HIPAA overlay if the CUI includes ePHI (e.g. military health data).
- IaC is brace/structure-checked only in the toolkit — run `terraform validate` / `cdk synth` before any apply.
