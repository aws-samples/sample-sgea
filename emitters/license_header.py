# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""MIT-0 header for source files and generated IaC (Amazon open source guidance, MIT-0 step 4)."""
import os

COPYRIGHT = "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved."
SPDX = "SPDX-License-Identifier: MIT-0"
COMMENT = {".py": "#", ".sh": "#", ".tf": "#", ".hcl": "#", ".ts": "//", ".js": "//", "Dockerfile": "#"}


def comment_for(path):
    name = os.path.basename(path)
    return COMMENT.get(name) or COMMENT.get(os.path.splitext(name)[1])


def has_header(text):
    return SPDX in "\n".join(text.splitlines()[:5])


def with_header(path, text):
    """`text` with the MIT-0 header (after a shebang); unchanged if present or the file type takes no comments."""
    c = comment_for(path)
    if not c or has_header(text):
        return text
    header = "%s %s\n%s %s\n" % (c, COPYRIGHT, c, SPDX)
    if text.startswith("#!"):
        first, _, rest = text.partition("\n")
        return first + "\n" + header + rest
    return header + text
