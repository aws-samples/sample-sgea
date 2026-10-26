# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Unit tests for the SGEA resolver and validator.

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_resolver.py

The second form needs no pytest — it discovers the test_* functions, runs
them, and prints a summary. Both forms exercise the real resolver against the
toolkit's shipped baselines and profiles.
"""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINES = os.path.join(ROOT, "baselines")
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, ROOT)
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402


def _resolve(name):
    return sgea.resolve(os.path.join(PROFILES, name), BASELINES)


# ---- deep_merge ---------------------------------------------------------
def test_deep_merge_scalar_replaces():
    out = sgea.deep_merge({"a": 1, "b": 2}, {"b": 3})
    assert out == {"a": 1, "b": 3}


def test_deep_merge_additive_catalogs_union():
    base = {"evidence": {"control_catalogs": ["x"]}}
    over = {"evidence": {"control_catalogs": ["y", "x"]}}
    out = sgea.deep_merge(base, over)
    assert out["evidence"]["control_catalogs"] == ["x", "y"]  # union, de-duped, ordered


def test_deep_merge_nonadditive_list_replaces():
    base = {"services": {"allow": ["a", "b", "c"]}}
    over = {"services": {"allow": ["a"]}}
    out = sgea.deep_merge(base, over)
    assert out["services"]["allow"] == ["a"]  # allow-list REPLACES (tightening)


def test_deep_merge_ignores_doc_keys():
    out = sgea.deep_merge({"a": 1}, {"_doc": "x", "_status": "y", "b": 2})
    assert out == {"a": 1, "b": 2}


# ---- resolve ------------------------------------------------------------
def test_reference_profile_resolves_and_validates():
    resolved, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert sgea.validate(resolved, PROFILES) == []
    assert resolved["profile"]["id"] == "fedramp-moderate-hipaa-commercial"
    assert resolved["partition"] == "aws"


def test_hipaa_overlay_unions_all_catalogs():
    resolved, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    cats = resolved["evidence"]["control_catalogs"]
    assert "nist-800-53-rev5-moderate" in cats
    assert "hipaa-security-rule" in cats
    assert "nist-800-66-rev2" in cats


def test_hipaa_overlay_forces_phi_and_eligibility():
    resolved, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert resolved["services"]["hipaa_eligible_only"] is True
    assert resolved["guardrails"]["pii"]["phi_entities"] is True


def test_low_relaxes_retention_and_catalog():
    resolved, _ = _resolve("fedramp-low.commercial.json")
    assert resolved["logging"]["retention_days"] == 90
    assert resolved["evidence"]["control_catalogs"] == ["nist-800-53-rev5-low"]


def test_part11_sets_seven_year_retention():
    resolved, _ = _resolve("fedramp-moderate-part11.commercial.json")
    assert resolved["logging"]["retention_days"] == 2555


# ---- validate (semantic) ------------------------------------------------
def test_govcloud_requires_gov_geo():
    resolved, _ = _resolve("dod-il4.govcloud.json")
    assert resolved["partition"] == "aws-us-gov"
    assert resolved["regions"]["inference_profile_geo"] == "us-gov"
    # Geo/partition coherence only; the IL4 service-authorization gap (AgentCore) is
    # covered by test_emitters_and_check.test_agentcore_not_authorized_for_il4_is_flagged.
    errs = [e for e in sgea.validate(resolved, PROFILES) if not e.startswith(sgea.DOWNGRADABLE)]
    assert errs == []


def test_validate_flags_partition_geo_mismatch():
    resolved, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    resolved["regions"]["inference_profile_geo"] = "us-gov"  # commercial + gov geo = invalid
    errs = sgea.validate(resolved, PROFILES)
    assert any("inference_profile_geo" in e for e in errs)


def test_validate_flags_hipaa_without_eligibility():
    resolved, _ = _resolve("fedramp-moderate-hipaa.commercial.json")
    resolved["services"]["hipaa_eligible_only"] = False  # contradicts hipaa baseline
    errs = sgea.validate(resolved, PROFILES)
    assert any("hipaa_eligible_only" in e for e in errs)


# ---- scaffold detection -------------------------------------------------
def test_scaffold_baselines_detected():
    _, prof = _resolve("fedramp-high.govcloud.json")
    assert sgea._baseline_status(prof, BASELINES) == "fedramp-high"
    _, prof2 = _resolve("dod-il4.govcloud.json")
    assert sgea._baseline_status(prof2, BASELINES) == "dod-il4"


def test_production_profile_not_scaffold():
    _, prof = _resolve("fedramp-moderate-hipaa.commercial.json")
    assert sgea._baseline_status(prof, BASELINES) is None


# ---- standalone runner (no pytest needed) -------------------------------
def _run():
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for n, f in fns:
        try:
            f(); passed += 1; print("  PASS  " + n)
        except Exception as e:  # noqa: BLE001
            failed += 1; print("  FAIL  " + n + "  -> " + repr(e))
    print("\n%d passed, %d failed, %d total" % (passed, failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
