# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The tenant-requirements doc shows exactly the compiled snippet code, and every language implements all five units."""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import tenant_snippets_docs as tsd  # noqa: E402

UNITS = ["caller", "converse", "gateway", "memory", "log"]


def test_every_language_implements_the_five_units_in_order():
    for _, _, rel in tsd.LANGS:
        text = open(os.path.join(tsd.BASE, rel)).read()
        found = [n for n, _ in tsd.REGION.findall(text)]
        assert found == UNITS, (rel, found)


def test_requirements_doc_matches_the_snippet_sources():
    assert tsd.render() == open(tsd.DOC).read(), "run: python3 -I tools/tenant_snippets_docs.py"


def test_requirement_ids_are_unique_and_sequential():
    import re
    ids = re.findall(r"^\| (TR-\d\d) \| (?:MUST|SHOULD) \|", open(tsd.DOC).read(), re.M)
    assert ids == ["TR-%02d" % i for i in range(1, len(ids) + 1)], ids


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            f(); print("  PASS  " + n)
