# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the audit-protection SCP statement group (ADR 0002, DenyAuditTampering).

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_policy_audit.py

Exercises every shipped profile through policy_library.bundles(); no AWS calls.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "emitters"))
os.environ.setdefault("SGEA_ROOT", ROOT)

import sgea  # noqa: E402
import derived, policy_library as pl  # noqa: E402

ALL_PROFILES = sorted(f for f in os.listdir(PROFILES) if f.endswith(".json") and not f.startswith("_"))
SCP = "SERVICE_CONTROL_POLICY"
AUDIT_ACTIONS = [
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
    "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
    "guardduty:DeleteDetector", "guardduty:DisassociateFromAdministratorAccount",
    "securityhub:DisableSecurityHub", "access-analyzer:DeleteAnalyzer",
]
KMS_ACTIONS = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy"]
BREAK_GLASS = "arn:${partition}:iam::*:role/sgea-*-break-glass"


def _resolve(name):
    return sgea.resolve(os.path.join(PROFILES, name))[0]


def _bundles(r):
    return pl.bundles(r, derived.authorized_model_ids(r, ROOT))


def _statements(bundles, ptype=SCP):
    out = []
    for b in bundles:
        if b["type"] == ptype:
            out += json.loads(pl._sample(b["template"]))["Statement"]
    return out


def _actions(stmts):
    acts = set()
    for s in stmts:
        a = s.get("Action", [])
        acts |= set([a] if isinstance(a, str) else a)
    return acts


def _audit_stmts(stmts):
    return [s for s in stmts if s.get("Sid", "").startswith("DenyAuditTampering")]


def test_every_profile_scps_carry_audit_protection_actions():
    for name in ALL_PROFILES:
        stmts = _audit_stmts(_statements(_bundles(_resolve(name))))
        acts = _actions(stmts)
        for a in AUDIT_ACTIONS + KMS_ACTIONS + ["logs:DeleteLogGroup"]:
            assert a in acts, (name, a)
        assert all(s["Effect"] == "Deny" for s in stmts), name
        assert sum(1 for b in _bundles(_resolve(name)) if "audit-protection" in b["statement_groups"]) == 1, name


def test_audit_protection_only_in_scps_not_rcps():
    for name in ALL_PROFILES:
        bs = _bundles(_resolve(name))
        assert not _audit_stmts(_statements(bs, "RESOURCE_CONTROL_POLICY")), name
        assert all(not b["statement_groups"] for b in bs if b["type"] != SCP), name


def test_audit_bundle_needs_no_deploy_time_inputs():
    # Must not be blocked when org_id / perimeter inputs are missing.
    for name in ALL_PROFILES:
        b = [b for b in _bundles(_resolve(name)) if "audit-protection" in b["statement_groups"]][0]
        assert b["needs"] == [], (name, b["needs"])


def test_log_group_deny_scoped_to_sgea_log_groups():
    r = _resolve("dod-il4.govcloud.json")
    s = [s for s in pl.scp_audit_protection(r)["Statement"] if "logs:DeleteLogGroup" in s["Action"]]
    assert len(s) == 1 and s[0]["Resource"] == ["arn:${partition}:logs:*:*:log-group:/sgea/*"]
    assert s[0]["Action"] == ["logs:DeleteLogGroup"]


def test_exemptions_present_on_every_statement():
    for name in ALL_PROFILES:
        stmts = _audit_stmts(_statements(_bundles(_resolve(name))))
        assert len(stmts) == 3, name
        part = _resolve(name)["partition"]
        for s in stmts:
            arns = s["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
            assert "arn:aws-us-gov:iam::*:role/sgea-*-break-glass" in arns, (name, s["Sid"])  # _sample partition
            assert any(":role/cdk-hnb659fds-cfn-exec-role-*" in a for a in arns), (name, s["Sid"])
        # Raw template uses the partition placeholder, never a hard-coded partition.
        raw = pl.scp_audit_protection(_resolve(name))
        assert "arn:aws:" not in json.dumps(raw) and "arn:aws-us-gov:" not in json.dumps(raw), (name, part)


def test_exempt_principal_input_threads_through():
    r = _resolve("fedramp-moderate-hipaa.commercial.json")
    extra = "arn:aws:iam::123456789012:role/pipeline-terraform-apply"
    r["policies"]["org_policy_exempt_principal_arns"] = [extra]
    for s in _audit_stmts(_statements(_bundles(r))):
        arns = s["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
        assert extra in arns and "arn:aws-us-gov:iam::*:role/sgea-*-break-glass" in arns, s["Sid"]
    assert pl.audit_exempt_principals(r)[-1] == extra
    assert BREAK_GLASS in pl.audit_exempt_principals(r)


def test_exempt_principal_input_validated_and_schema_accepts_it():
    r = _resolve("fedramp-low.commercial.json")
    r["policies"]["org_policy_exempt_principal_arns"] = "not-a-list"
    try:
        pl.scp_audit_protection(r)
    except SystemExit:
        pass
    else:
        raise AssertionError("non-list exempt principals accepted")
    r["policies"]["org_policy_exempt_principal_arns"] = ["arn:aws:iam::123456789012:role/deployer"]
    assert not [e for e in sgea.validate(r, PROFILES) if e.startswith("schema:")]


def test_kms_denies_carry_profile_tag_condition():
    for name in ALL_PROFILES:
        stmts = _audit_stmts(_statements(_bundles(_resolve(name))))
        kms = [s for s in stmts if set(_actions([s])) & set(KMS_ACTIONS)]
        assert len(kms) == 1, name
        s = kms[0]
        assert sorted(s["Action"]) == sorted(KMS_ACTIONS), name
        assert s["Condition"]["Null"] == {"aws:ResourceTag/sgea:profile": "false"}, name
        # Non-KMS audit statements are not tag-conditioned.
        assert all("Null" not in o["Condition"] for o in stmts if o is not s), name


def test_bundle_count_and_sizes_within_limits():
    for name in ALL_PROFILES:
        r = _resolve(name)
        for extra in ([], ["arn:aws:iam::123456789012:role/deploy-%d" % i for i in range(5)]):
            r["policies"]["org_policy_exempt_principal_arns"] = extra
            bs = _bundles(r)
            for t in (SCP, "RESOURCE_CONTROL_POLICY"):
                assert len([b for b in bs if b["type"] == t]) <= pl.MAX_ATTACHED, (name, t, len(extra))
            for b in bs:
                assert len(pl._sample(b["template"])) <= pl.SCP_MAX_CHARS, (name, b["name"], len(extra))
            # Baseline-selected packs are unchanged by the always-on group.
            assert sorted(p for b in bs for p in b["packs"]) == sorted(r["policies"]["scps"] + r["policies"]["rcps"])


def test_bundles_are_valid_json_after_substitution():
    for name in ALL_PROFILES:
        for b in _bundles(_resolve(name)):
            doc = json.loads(pl._sample(b["template"]))
            assert doc["Version"] == "2012-10-17" and doc["Statement"], (name, b["name"])
            sids = [s["Sid"] for s in doc["Statement"]]
            assert len(sids) == len(set(sids)), (name, b["name"])


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
