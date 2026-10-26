<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/dod-il4.json and are emitted by ../../sgea.py. -->

# DoD IL4 (GovCloud) — Open Items & Caveats

This vertical is **unverified scaffold**. Before it can be used in production:

0. Stand up the DoD Secure Cloud Computing Architecture (SCCA) boundary: BCAP connection (DISA, customer-arranged), VDSS inspection (emitted by SGEA as AWS Network Firewall), VDMS monitoring (emitted: GuardDuty, Security Hub NIST 800-53), TCCM process.
1. Confirm Amazon Bedrock + AgentCore availability in AWS GovCloud (US) and their inclusion in the AWS DoD Provisional Authorization at IL4 (AWS Artifact).
2. Re-resolve every service in the allow-list against GovCloud service availability AND IL4 PA scope.
3. Validate the control mapping (NIST SP 800-53 Rev 5 Moderate + DoD SRG IL4) with the DoD AO.
4. Document the DoD-specific personnel/access controls (US-person restrictions, background investigations) — these are process controls, not IaC.
5. Rebuild and test the IaC in a GovCloud sandbox under the mission owner's own SCPs.
6. Remove the `scaffold-unverified` status in `baselines/dod-il4.json` only after the above.

Other notes:
- Add the HIPAA overlay if the CUI includes ePHI (e.g. military health data).
- IaC is brace/structure-checked only in the toolkit — run `terraform validate` / `cdk synth` before any apply.
