#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
MIT-0 source-file headers (Amazon open source guidance, "Licensing for GitHub Projects → MIT-0", step 4).

  python3 -I tools/license_headers.py          # add the header to every tracked source file that lacks it
  python3 -I tools/license_headers.py --check  # list files without it (exit 1 if any)

The emitters use `with_header()` so generated Terraform / CDK / Lambda files carry the same header.
"""
import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "emitters"))
from license_header import SPDX, comment_for, has_header, with_header  # noqa: E402,F401

# Files that never ship in the public distribution (tools/make_public.py excludes them) carry no MIT-0 header.
SKIP_PREFIXES = ("collateral/", "sources/", "tools/make_public.py")


def tracked_sources(root=ROOT):
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split()  # nosec B603 B607
    return [f for f in files if comment_for(f) and not f.startswith(SKIP_PREFIXES) and "node_modules/" not in f]


def main(argv=None):
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    missing = []
    for rel in tracked_sources():
        p = os.path.join(ROOT, rel)
        text = open(p).read()
        if has_header(text):
            continue
        missing.append(rel)
        if not check:
            open(p, "w").write(with_header(rel, text))
    if check:
        print("\n".join(missing) if missing else "all source files have the MIT-0 header")
        return 1 if missing else 0
    print("added the MIT-0 header to %d file(s)" % len(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
