<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/hipaa.json and are emitted by ../../sgea.py. -->

# HIPAA (overlay) — Open Items & Caveats

- HIPAA responsibility labels in the CRM are the toolkit's mapping — **ISSO review required**.
- Confirm the BAA is accepted at the account level before any ePHI is introduced.
- Confirm every production service in-boundary is HIPAA-eligible for the composed partition.
- Guardrail coverage of PHI inside Knowledge Base RetrieveAndGenerate and AgentCore Memory internal calls is not yet confirmed — verify it against the current AWS documentation before relying on it.
