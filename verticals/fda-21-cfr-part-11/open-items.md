<!-- Part of the Secure GenAI Enclave Accelerator (SGEA) toolkit. Authoritative control values live in ../../baselines/fda-21-cfr-part-11.json (an overlay) and are emitted by ../../sgea.py. -->

# FDA 21 CFR Part 11 / GxP (overlay) — Open Items & Caveats

- Part 11 is partly a **process** framework: electronic-signature binding and CSV are not fully expressible in IaC — assign them to the quality/validation team.
- Confirm the audit log store is configured write-once (object lock) to meet the immutable-audit-trail expectation.
- If ePHI is involved, add the HIPAA overlay (BAA, PHI entities, HIPAA-eligible-only surface).
- IaC is brace/structure-checked only — validate in a sandbox before production.
