#!/usr/bin/env bash
# Build the sample agent (linux/arm64 — AgentCore Runtime) and push it to the ENCLAVE's ECR
# repository with an immutable, content-derived tag. Prints the image URI.
#   usage: build_push.sh <agents_repository_url> <region>
# Uses finch (or docker if FINCH=docker). AWS credentials must be in the environment.
set -euo pipefail
REPO="$1"; REGION="$2"; ENGINE="${FINCH:-finch}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TAG="v$(cat "$HERE/app/agent.py" "$HERE/app/Dockerfile" | shasum -a 256 | cut -c1-12)"
REGISTRY="${REPO%%/*}"
aws ecr get-login-password --region "$REGION" | "$ENGINE" login --username AWS --password-stdin "$REGISTRY" >/dev/null
if aws ecr describe-images --region "$REGION" --repository-name "${REPO#*/}" --image-ids imageTag="$TAG" >/dev/null 2>&1; then
  echo "$REPO:$TAG"; exit 0   # immutable tag already pushed
fi
"$ENGINE" build --platform linux/arm64 -t "$REPO:$TAG" "$HERE/app" >&2
"$ENGINE" push "$REPO:$TAG" >&2
echo "$REPO:$TAG"
