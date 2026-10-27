#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA sandbox end-to-end test: deploy the enclave + the sample agent into ONE sandbox account,
# run the e2e test, leave everything up for inspection. Tear down with tools/sandbox_teardown.py.
#
#   examples/run_sandbox_test.sh <credentials> [profile.json] --yes [--cdk]
#
# <credentials>: an AWS CLI profile name (exported as AWS_PROFILE; static AWS_* keys are dropped)
# or `env` (the ambient credential chain as-is: AWS_* environment variables, instance role).
# The region is always the profile's resolved primary region. Set SGEA_EXPECT_ACCOUNT_ID=<12 digits> to refuse
# to deploy unless the credentials belong to that account (tools/sandbox_matrix.sh always sets it).
#
# --cdk deploys the enclave from the CDK app (gate: `sgea check --cfn` on the synthesized
# templates) instead of Terraform; network, tenant app and e2e test are the same. Its state lives
# in .sandbox/<profile-id>-cdk. Only one enclave per account at a time (fixed resource names).
#
# Creates REAL, BILLABLE resources (VPC endpoints, Aurora Serverless v2, Network Firewall for
# IL4/IL5, KMS keys, CloudTrail, Config). Every apply is gated on `sgea check` of its plan.
set -euo pipefail
CRED_KINDS="aws-profile | env"
CREDS="${1:?usage: run_sandbox_test.sh <credentials: $CRED_KINDS> [profile.json] --yes [--cdk]}"
PROFILE="${2:-profiles/fedramp-moderate-hipaa.commercial.json}"
[[ "$PROFILE" == --* ]] && PROFILE=profiles/fedramp-moderate-hipaa.commercial.json   # `<credentials> --yes`
[[ " $* " == *" --yes "* ]] || { echo "Refusing to create billable resources without --yes"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
ENV_NAME="${SGEA_ENV:-sbx}"
REGION="$(python3 -c "import sys,json;sys.path.insert(0,'.');import sgea;r,_=sgea.resolve('$PROFILE');print(r['regions']['primary'])")"
PID="$(python3 -c "import sys;sys.path.insert(0,'.');import sgea;r,_=sgea.resolve('$PROFILE');print(r['profile']['id'])")"
CDK_MODE=false; [[ " $* " == *" --cdk "* ]] && CDK_MODE=true
BUILD="build/$PID"; TF="$BUILD/terraform"; CDK="$BUILD/cdk"
STATE="$ROOT/.sandbox/$PID"; $CDK_MODE && STATE="$STATE-cdk"; mkdir -p "$STATE"
case "$CREDS" in
  env)  # ambient credential chain as-is
    export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION" ;;
  *)    # AWS CLI profile; static keys in the environment would take precedence over it
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    export AWS_PROFILE="$CREDS" AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION" ;;
esac
ACCT_ID="$(aws sts get-caller-identity --query Account --output text)" \
  || { echo "cannot resolve credentials '$CREDS' (aws sts get-caller-identity failed)"; exit 2; }
if [[ -n "${SGEA_EXPECT_ACCOUNT_ID:-}" && "$ACCT_ID" != "$SGEA_EXPECT_ACCOUNT_ID" ]]; then
  echo "refusing: credentials are for $ACCT_ID, not $SGEA_EXPECT_ACCOUNT_ID"; exit 6
fi
echo "== account $ACCT_ID  profile $PID  region $REGION  env $ENV_NAME"

echo "== 1/6 sandbox network"
# One sandbox network for every profile / engine run (fixed CIDR; AgentCore ENIs make VPC deletion slow).
NET="$ROOT/.sandbox/_network"; mkdir -p "$NET"
terraform -chdir=examples/sandbox-network init -input=false -reconfigure -backend-config="path=$NET/network.tfstate" >/dev/null
terraform -chdir=examples/sandbox-network apply -input=false -auto-approve -var "region=$REGION"
terraform -chdir=examples/sandbox-network output -json enclave_inputs > "$STATE/network.json"

echo "== 2/6 export + plan + check + apply the enclave"
python3 sgea.py export --profile "$PROFILE" --out build/ --allow-unverified
# Preflight: manual steps that need an AWS request (MANUAL-STEPS.md section 1). Fail before creating anything.
NEED=$(python3 -c "
import sys; sys.path.insert(0, 'emitters'); import sgea, derived, manual_steps
r, _ = sgea.resolve('$PROFILE'); q = manual_steps.lambda_quota_need(r, '.')
print(q[0] if q else 0)")
if [[ "$NEED" -gt 0 ]]; then
  HAVE=$(aws service-quotas get-service-quota --service-code lambda --quota-code L-B99A9384 --query 'Quota.Value' --output text 2>/dev/null || echo 0)
  if python3 -c "import sys; sys.exit(0 if float('$HAVE') >= $NEED else 1)"; then
    echo "preflight: Lambda concurrent-executions quota $HAVE >= $NEED"
  else
    echo "preflight FAILED: Lambda concurrent-executions quota is $HAVE, the profile needs >= $NEED."
    echo "  Request it first (see $BUILD/MANUAL-STEPS.md, section 1)."; exit 3
  fi
fi
# Decide sandbox settings ONCE (first run) and reuse them: re-detecting would see the enclave's own
# Config recorder / Security Hub from a previous run and tell Terraform to delete them.
if [[ ! -f "$STATE/sandbox.auto.tfvars.json" ]]; then
  has() { "$@" >/dev/null 2>&1; }
  GD=$(aws guardduty list-detectors --query 'length(DetectorIds)' --output text); SH=false; has aws securityhub describe-hub && SH=true
  REC=$(aws configservice describe-configuration-recorders --query 'length(ConfigurationRecorders)' --output text)
  python3 - "$STATE/sandbox.auto.tfvars.json" "$ENV_NAME" "$GD" "$SH" "$REC" <<'PY'
import json, sys
path, env, gd, sh, rec = sys.argv[1:]
json.dump({"env": env, "deploy_org_policies": False,          # sandbox is not an Organizations management account
           "create_guardduty": gd == "0", "create_securityhub": sh != "true",
           "create_config_recorder": rec == "0"}, open(path, "w"), indent=2)
PY
fi
cat "$STATE/sandbox.auto.tfvars.json"
if $CDK_MODE; then
  (cd "$CDK" && { [[ -d node_modules ]] || npm ci --no-audit --no-fund >/dev/null; })
  CTX=$(python3 - "$STATE/network.json" "$STATE/sandbox.auto.tfvars.json" <<'PY'
import json, sys
n, sb = (json.load(open(p)) for p in sys.argv[1:])
ctx = {"env": sb["env"], "vpcId": n["vpc_id"], "endpointSubnetIds": n["endpoint_subnet_ids"],
       "endpointSecurityGroupIds": n["endpoint_security_group_ids"], "endpointRouteTableIds": n["endpoint_route_table_ids"],
       "auroraSubnetIds": n["aurora_subnet_ids"], "auroraSecurityGroupIds": n["aurora_security_group_ids"],
       "agentSubnetIds": n["agent_subnet_ids"], "agentSecurityGroupIds": n["agent_security_group_ids"],
       "sccaFirewallSubnetIds": n.get("scca_firewall_subnet_ids", []),
       "deployOrgPolicies": sb["deploy_org_policies"], "createGuardDuty": sb["create_guardduty"],
       "createSecurityHub": sb["create_securityhub"], "createConfigRecorder": sb["create_config_recorder"]}
print(" ".join("-c sgea:%s=%s" % (k, ",".join(v) if isinstance(v, list) else str(v).lower() if isinstance(v, bool) else v)
               for k, v in ctx.items() if v != []))   # comma lists: no spaces (word-split by the shell)
PY
)
  ACCT="$ACCT_ID"
  (cd "$CDK" && npx cdk bootstrap "aws://$ACCT/$REGION" $CTX >/dev/null)
  REPLICA=$(python3 -c "import json;print(json.load(open('$CDK/config.json'))['_derived']['replica_region'] or '')")
  [[ -n "$REPLICA" ]] && (cd "$CDK" && npx cdk bootstrap "aws://$ACCT/$REPLICA" $CTX >/dev/null)
  (cd "$CDK" && npx cdk synth $CTX >/dev/null)
  CFN=(); for t in "$CDK"/cdk.out/*.template.json; do CFN+=(--cfn "$t"); done
  python3 sgea.py check --out "$BUILD" "${CFN[@]}" --allow-gaps   # gate: exit 5 on any required FAIL
  (cd "$CDK" && npx cdk deploy --all --require-approval never --no-rollback --outputs-file "$STATE/cdk-outputs.json" $CTX)
  python3 -c "
import json; o = json.load(open('$STATE/cdk-outputs.json'))['SgeaEnclave']
json.dump(json.loads(next(v for k, v in o.items() if k.startswith('Enclave'))), open('$STATE/enclave.json', 'w'), indent=2)"
else
cp "$STATE/network.json" "$TF/network.auto.tfvars.json"
cp "$STATE/sandbox.auto.tfvars.json" "$TF/sandbox.auto.tfvars.json"
printf 'terraform {\n  backend "local" {\n    path = "%s/enclave.tfstate"\n  }\n}\n' "$STATE" > "$TF/backend_override.tf"
terraform -chdir="$TF" init -input=false -reconfigure >/dev/null
terraform -chdir="$TF" plan -input=false -out=tfplan >/dev/null
terraform -chdir="$TF" show -json tfplan > "$STATE/enclave-plan.json"
python3 sgea.py check --out "$BUILD" --plan "$STATE/enclave-plan.json" --allow-gaps   # gate: exit 5 on any required FAIL
terraform -chdir="$TF" apply -input=false tfplan
terraform -chdir="$TF" output -json enclave > "$STATE/enclave.json"
fi

echo "== 3/6 build + push the agent image to the enclave ECR"
REPO=$(python3 -c "import json;print(json.load(open('$STATE/enclave.json'))['agents_repository_url'])")
IMAGE=$(examples/sample-agent/scripts/build_push.sh "$REPO" "$REGION")
echo "image: $IMAGE"

echo "== 4/6 deploy the sample tenant app"
INFRA=examples/sample-agent/infra
ln -sfn "$ROOT/$TF/modules" "$INFRA/.sgea-modules"
python3 - "$STATE" "$IMAGE" <<'PY'
import json, sys
state, image = sys.argv[1:]
json.dump({"enclave": json.load(open(state + "/enclave.json")), "network": json.load(open(state + "/network.json")),
           "image_uri": image}, open(state + "/sample.tfvars.json", "w"), indent=2)
PY
terraform -chdir="$INFRA" init -input=false -reconfigure -backend-config="path=$STATE/sample.tfstate" >/dev/null
terraform -chdir="$INFRA" apply -input=false -auto-approve -var-file="$STATE/sample.tfvars.json"
terraform -chdir="$INFRA" output -json > "$STATE/sample-outputs.json"

echo "== 5/6 end-to-end test"
python3 examples/sample-agent/scripts/e2e_test.py "$STATE/sample-outputs.json"

echo "== 6/6 done — state in $STATE. Tear down: python3 tools/sandbox_teardown.py --account $CREDS --account-id <account-id> --profile $PROFILE$($CDK_MODE && echo ' --cdk')"
