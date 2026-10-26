"""
Tests for the generated per-framework docs (docs/frameworks/, from tools/framework_docs.py).

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_framework_docs.py

Every catalog baseline has a doc, the committed docs equal the generator output (regenerated into a
temp dir), and no doc carries an AWS account id or AWS Artifact text.
"""
import os, re, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "catalog")
DOCS = os.path.join(ROOT, "docs", "frameworks")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
os.environ.setdefault("SGEA_ROOT", ROOT)

import framework_docs  # noqa: E402

BASELINES = sorted(f[:-5] for f in os.listdir(CATALOG) if f.endswith(".json") and not f.startswith("_"))


def _committed():
    return {f: open(os.path.join(DOCS, f)).read() for f in sorted(os.listdir(DOCS)) if f.endswith(".md")}


def test_every_catalog_baseline_has_a_doc_and_index_row():
    docs = _committed()
    assert BASELINES, "no catalog baselines found"
    for b in BASELINES:
        assert b + ".md" in docs, "missing docs/frameworks/%s.md" % b
        assert "](%s.md)" % b in docs["README.md"], "index does not link %s" % b
        assert b in framework_docs.FRAMEWORKS, "no description for %s in framework_docs.FRAMEWORKS" % b
    assert set(docs) == {b + ".md" for b in BASELINES} | {"README.md"}, "stale doc for a removed baseline"


def test_docs_are_up_to_date_with_the_generator():
    with tempfile.TemporaryDirectory() as tmp:
        assert framework_docs.main(["--out", tmp]) == 0
        fresh = {f: open(os.path.join(tmp, f)).read() for f in sorted(os.listdir(tmp))}
    committed = _committed()
    assert set(fresh) == set(committed)
    stale = [f for f in fresh if fresh[f] != committed[f]]
    assert not stale, "docs/frameworks out of date (run python3 -I tools/framework_docs.py): %s" % stale


def test_no_account_ids_or_artifact_text():
    for f, text in _committed().items():
        assert not re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", text), "%s: looks like an AWS account id" % f
        assert "AWS Artifact text omitted" not in text, f
        assert not re.search(r"report-[A-Za-z0-9]{8,}", text), "%s: AWS Artifact report id" % f
        assert "_nda" not in text and "sources/artifact" not in text, f


def test_doc_counts_match_the_catalog():
    import json
    for b in BASELINES:
        cat = json.load(open(os.path.join(CATALOG, b + ".json")))
        text = open(os.path.join(DOCS, b + ".md")).read()
        checked = sum(1 for v in cat["coverage"].values() if v["status"] == "checked")
        assert "%d AWS Config rules in the composed pack(s)" % cat["rule_count"] in text, b
        assert re.search(r"\| \[`checked`\]\([^)]*\) \| [^|]+ \| %d \|" % checked, text), b
        for s in cat["sources"]:
            assert s["pack_url"] in text, b


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
