#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA sandbox matrix: every commercial-region profile x {terraform, cdk}, one at a time:
#   deploy (gated on sgea check) -> 7-check e2e -> teardown (keeps the shared sandbox network).
# Results are appended to docs/SANDBOX-MATRIX.md; full logs in /tmp/sgea-matrix/.
#
#   tools/sandbox_matrix.sh <credentials> <account-id> --yes [profile.json[:terraform|:cdk] ...]
#
# <credentials>: an AWS CLI profile name or `env` (ambient credential chain as-is); see
# examples/run_sandbox_test.sh.
# Teardown needs a boto3 with bedrock-agentcore-control: /tmp/sgea-boto ($SGEA_BOTO; tools/bootstrap_sdk.sh)
# if it exists, else python3's own boto3; the teardown exits before deleting anything if it is missing.
#
# Creates and destroys REAL, BILLABLE resources, ~1 hour per run. SANDBOX ONLY: every deploy and
# teardown refuses to run unless the credentials' account equals <account-id>.
set -uo pipefail
CRED_KINDS="aws-profile | env"
USAGE="usage: sandbox_matrix.sh <credentials: $CRED_KINDS> <account-id> --yes [profiles...]"
CREDS="${1:?$USAGE}"
ACCOUNT_ID="${2:?$USAGE}"
[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || { echo "account id must be 12 digits: $ACCOUNT_ID"; exit 2; }
[[ "${3:-}" == "--yes" ]] || { echo "Refusing to create billable resources without --yes"; exit 2; }
shift 3
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PROFILES=("$@")
if [[ ${#PROFILES[@]} -eq 0 ]]; then PROFILES=(profiles/*.commercial.json); fi
LOGS=/tmp/sgea-matrix; mkdir -p "$LOGS"
OUT=docs/SANDBOX-MATRIX.md
[[ -f "$OUT" ]] || printf '# SGEA sandbox matrix\n\n| date (UTC) | profile | engine | deploy | e2e | teardown | log |\n|---|---|---|---|---|---|---|\n' > "$OUT"

for ARG in "${PROFILES[@]}"; do
  P="${ARG%%:*}"; ENGINES="terraform cdk"; [[ "$ARG" == *:* ]] && ENGINES="${ARG##*:}"
  PID=$(python3 -c "import sys;sys.path.insert(0,'.');import sgea;r,_=sgea.resolve('$P');print(r['profile']['id'])")
  for ENGINE in $ENGINES; do
    FLAG=""; [[ "$ENGINE" == cdk ]] && FLAG="--cdk"
    LOG="$LOGS/$PID-$ENGINE.log"; TLOG="$LOGS/$PID-$ENGINE-teardown.log"
    echo "== $(date -u +%H:%M) $PID / $ENGINE  (log $LOG)"
    SGEA_EXPECT_ACCOUNT_ID="$ACCOUNT_ID" examples/run_sandbox_test.sh "$CREDS" "$P" --yes $FLAG > "$LOG" 2>&1; RC=$?
    if [[ $RC -eq 6 ]]; then tail -1 "$LOG"; echo "wrong account: stopping the matrix"; exit 6; fi
    E2E=$(grep -E '^[0-9]+/[0-9]+ passed' "$LOG" | tail -1)
    if [[ $RC -eq 0 ]]; then DEPLOY=ok; elif [[ -n "$E2E" ]]; then DEPLOY=ok; else DEPLOY="FAILED (rc $RC): $(grep -m1 -E 'Error:|CREATE_FAILED|preflight FAILED|check:.*FAIL' "$LOG" | cut -c1-120 | tr '|' '/')"; fi
    [[ -z "$E2E" ]] && E2E="not run"
    echo "   deploy: $DEPLOY   e2e: $E2E"
    EVID=""; [[ "$DEPLOY" != ok ]] && EVID="--no-evidence"   # a failed / partial deploy must not overwrite good evidence
    echo "$ACCOUNT_ID" | python3 tools/sandbox_teardown.py --account "$CREDS" --account-id "$ACCOUNT_ID" \
        --profile "$P" $FLAG $EVID > "$TLOG" 2>&1 && TD=ok || TD="FAILED: $(grep -m1 -E 'Error|Exception' "$TLOG" | cut -c1-100 | tr '|' '/')"
    echo "   teardown: $TD"
    printf '| %s | %s | %s | %s | %s | %s | `%s` |\n' "$(date -u +%Y-%m-%dT%H:%MZ)" "$PID" "$ENGINE" "$DEPLOY" "$E2E" "$TD" "$LOG" >> "$OUT"
    if [[ "$TD" != ok ]]; then echo "teardown failed: stopping the matrix (fixed resource names would collide)"; exit 4; fi
  done
done
echo "matrix done: $OUT"
