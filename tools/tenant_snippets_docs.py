#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Fill the code blocks in docs/operations/tenant-requirements.md from the compiled snippet sources in examples/tenant-snippets/, so the documented code is exactly the code CI builds.

  python3 -I tools/tenant_snippets_docs.py          # rewrite the blocks
  python3 -I tools/tenant_snippets_docs.py --check  # exit 1 if the doc is stale (tests use this)

Each source marks regions with `<comment> sgea:snippet:start <name>` / `<comment> sgea:snippet:end`; the doc has `<!-- sgea:snippet-block <name> -->` ... `<!-- /sgea:snippet-block -->`.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "operations", "tenant-requirements.md")
BASE = os.path.join(ROOT, "examples", "tenant-snippets")
LANGS = [("Python", "python", "python/sgea_tenant.py"),
         ("Node.js (TypeScript)", "typescript", "node/src/sgeaTenant.ts"),
         (".NET (C#)", "csharp", "dotnet/SgeaTenant.cs"),
         ("Java", "java", "java/src/main/java/com/example/sgea/SgeaTenant.java")]
REGION = re.compile(r"^[ \t]*(?:#|//)[ \t]*sgea:snippet:start[ \t]+(\w+)[ \t]*\n(.*?)^[ \t]*(?:#|//)[ \t]*sgea:snippet:end[ \t]*$", re.S | re.M)
BLOCK = re.compile(r"(<!-- sgea:snippet-block (\w+) -->\n)(.*?)(<!-- /sgea:snippet-block -->)", re.S)


def regions(rel):
    text = open(os.path.join(BASE, rel)).read()
    out = {}
    for name, body in REGION.findall(text):
        lines = body.rstrip("\n").split("\n")
        indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
        out[name] = "\n".join(l[indent:] for l in lines)
    return out


def render():
    src = {rel: regions(rel) for _, _, rel in LANGS}
    doc = open(DOC).read()

    def block(m):
        name, parts = m.group(2), []
        for i, (label, fence, rel) in enumerate(LANGS):
            if name not in src[rel]:
                raise SystemExit("snippet %r missing in examples/tenant-snippets/%s" % (name, rel))
            parts.append("<details%s>\n<summary>%s — <code>%s</code></summary>\n\n```%s\n%s\n```\n\n</details>\n"
                         % (" open" if i == 0 else "", label, rel, fence, src[rel][name]))
        return m.group(1) + "\n".join(parts) + m.group(4)

    return BLOCK.sub(block, doc)


def main(argv=None):
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    new = render()
    if check:
        stale = new != open(DOC).read()
        print("docs/operations/tenant-requirements.md is %s" % ("STALE: run python3 -I tools/tenant_snippets_docs.py" if stale else "up to date"))
        return 1 if stale else 0
    open(DOC, "w").write(new)
    print("docs/operations/tenant-requirements.md: snippets filled from examples/tenant-snippets/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
