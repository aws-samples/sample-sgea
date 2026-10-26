#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Install a current boto3/botocore (with bedrock-agentcore-control) into a private directory that
# tools/sandbox_teardown.py and tools/collect_evidence.py put first on sys.path when it exists, so an
# older botocore elsewhere (e.g. user site-packages) cannot shadow it.
#
#   tools/bootstrap_sdk.sh [dir]        # default: $SGEA_BOTO, else /tmp/sgea-boto (does not survive a reboot)
#
# Equivalent by hand: python3 -m pip install --upgrade --target /tmp/sgea-boto boto3
set -euo pipefail
DIR="${1:-${SGEA_BOTO:-/tmp/sgea-boto}}"
python3 -m pip install --quiet --upgrade --target "$DIR" boto3
PYTHONPATH="$DIR" python3 -s -c "
import sys, boto3
ok = 'bedrock-agentcore-control' in boto3.session.Session().get_available_services()
print('%s: boto3 %s, bedrock-agentcore-control %s' % (sys.argv[1], boto3.__version__, 'available' if ok else 'MISSING'))
sys.exit(0 if ok else 1)" "$DIR"
[[ "$DIR" == /tmp/sgea-boto || "${SGEA_BOTO:-}" == "$DIR" ]] || echo "export SGEA_BOTO=$DIR   # so the sandbox tools find it"
