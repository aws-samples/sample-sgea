# SGEA Compliance Verticals

> **Sample code — not for production use as is.** SGEA is sample code for demonstration and evaluation. It has not completed a security review for your environment and is not intended for production use without your own security review, testing and authorization. Deploying it does not make a system compliant with, or authorized under, any framework: that is determined by your assessor or authorizing official for your whole system.

Each compliance vertical has its own folder with the documentation an adopter needs: an overview, what it configures, the responsibility and evidence model, and open items. The **authoritative control values** live in `../baselines/<vertical>.json` and are emitted by `../sgea.py`; these docs explain and surround them.

A vertical is one of two kinds:
- **Baseline** — a complete enclave definition (sets partition, regions, controls). FedRAMP Moderate and FedRAMP High are baselines.
- **Overlay** — tightens a baseline for a specific data type; it does not set partition/regions on its own. HIPAA is an overlay. Overlays stack on a baseline (e.g. Moderate + HIPAA).

## Shipped

| Vertical | Kind | Status | Folder |
|---|---|---|---|
| FedRAMP Low (commercial) | Baseline | Sandbox-validated sample | [`fedramp-low/`](fedramp-low/) |
| FedRAMP Moderate (commercial) | Baseline | Sandbox-validated sample (reference) | [`fedramp-moderate/`](fedramp-moderate/) |
| FedRAMP High (GovCloud) | Baseline | Scaffold — unverified | [`fedramp-high/`](fedramp-high/) |
| DoD IL4 (GovCloud) | Baseline | Scaffold — unverified | [`dod-il4/`](dod-il4/) |
| HIPAA | Overlay | Sandbox-validated sample (ISSO-review labels) | [`hipaa/`](hipaa/) |
| HITRUST CSF | Overlay | Sandbox-validated sample (assessor/ISSO-review labels) | [`hitrust/`](hitrust/) |
| FDA 21 CFR Part 11 / GxP | Overlay | Platform controls ready; signatures/CSV are process | [`fda-21-cfr-part-11/`](fda-21-cfr-part-11/) |

Each folder contains: `README.md` (overview + config table + deploy), `responsibility-matrix.md` (four-layer split + control catalogs + CRM profile), `open-items.md` (caveats + verification steps).

## Candidate frameworks (roadmap)

These are frameworks the toolkit could add. Each is tagged as a **baseline** (its own partition/control set) or an **overlay** (tightens a FedRAMP base), with the partition it typically needs. None are built yet — they are scoped here so a profile can be scaffolded on demand.

### Federal / government
| Framework | Kind | Partition | Notes |
|---|---|---|---|
| **DoD SRG IL5** | Baseline | GovCloud | Higher-sensitivity CUI / NSS; dedicated infrastructure rules. |
| **CMMC 2.0 (L2)** | Overlay | Commercial/GovCloud | Defense-contractor cert built on NIST SP 800-171. |
| **NIST SP 800-171** | Overlay | Either | CUI in non-federal systems; underpins CMMC. |
| **CJIS Security Policy** | Overlay | GovCloud (typical) | Criminal-justice information; law-enforcement tenants. |
| **IRS Publication 1075** | Overlay | GovCloud (typical) | Federal Tax Information (FTI). |
| **ITAR / EAR** | Overlay | GovCloud | Export-controlled data; GovCloud is effectively required. |
| **StateRAMP / TX-RAMP** | Baseline | Commercial | State-government equivalents of FedRAMP. |
| **CMS MARS-E / ARS** | Overlay | Commercial | CMS / Medicaid data; aligns closely with 800-53 + HIPAA. |

### Healthcare / life sciences
| Framework | Kind | Partition | Notes |
|---|---|---|---|
| **42 CFR Part 2** | Overlay | Commercial | Substance-use-disorder records; stricter than HIPAA on disclosure. |

### Commercial / cross-industry
| Framework | Kind | Partition | Notes |
|---|---|---|---|
| **SOC 2 (Type II)** | Overlay | Commercial | Trust-services criteria; common commercial ask. |
| **ISO/IEC 27001** | Overlay | Commercial | International ISMS standard. |
| **PCI DSS** | Overlay | Commercial | Payment-card data; relevant only if PANs enter the enclave. |
| **NIST CSF 2.0** | Overlay | Either | General cyber-risk framework; useful as a crosswalk layer. |

### Privacy (data-handling overlays)
| Framework | Kind | Partition | Notes |
|---|---|---|---|
| **FERPA** | Overlay | Commercial | Student education records. |
| **GDPR / CCPA** | Overlay | Either | Personal-data privacy; mostly data-handling + guardrail/PII posture. |

## Recommended next additions

Given the toolkit's federal + healthcare roots, the highest-value remaining additions are, in order:
1. **CMMC 2.0 / NIST 800-171** — one overlay unlocks the defense-industrial-base audience; pairs naturally with the DoD IL4 baseline.
2. **DoD IL5** — higher-sensitivity CUI / NSS; builds on the IL4 GovCloud work.
3. **42 CFR Part 2** — compounds the HIPAA/HITRUST healthcare overlays for substance-use-disorder records.

_Shipped since first roadmap: FedRAMP Low, DoD IL4, HITRUST CSF, and FDA 21 CFR Part 11 / GxP (see the Shipped table above)._

Each new vertical is a baseline or overlay JSON under `../baselines/`, a profile under `../profiles/`, and a folder here — the generator and emitters do not change.
