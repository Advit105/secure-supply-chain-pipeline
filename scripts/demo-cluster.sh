#!/usr/bin/env bash
# Reproduce the admission-gate demo locally: k3d + Kyverno + the two policies,
# then try to deploy the signed-but-vulnerable image and watch it get REJECTED.
# Needs: docker, k3d, kubectl, aws (configured). Registry stays real (ECR);
# only the cluster is local — free-tier friendly and offline-cluster.
set -euo pipefail
cd "$(dirname "$0")/.."

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text) # your account, not a hardcode
REG="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
KYVERNO_VER=$(curl -s https://api.github.com/repos/kyverno/kyverno/releases/latest | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")

echo "==> cluster"
k3d cluster create supply-chain --wait --timeout 180s 2>/dev/null || echo "  (exists)"

echo "==> Kyverno $KYVERNO_VER"
kubectl create -f "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VER/install.yaml" 2>/dev/null || true
kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=180s

echo "==> namespace + ECR pull creds (Kyverno reads signatures; kubelet pulls)"
kubectl apply -f k8s/namespace.yaml
PASS=$(aws ecr get-login-password)
for ns in kyverno demo; do
  kubectl delete secret ecr-creds -n "$ns" >/dev/null 2>&1 || true
  kubectl create secret docker-registry ecr-creds -n "$ns" \
    --docker-server="$REG" --docker-username=AWS --docker-password="$PASS"
done
kubectl patch serviceaccount default -n demo -p '{"imagePullSecrets":[{"name":"ecr-creds"}]}'
# point Kyverno's admission controller at the pull secret (idempotent)
kubectl -n kyverno patch deployment kyverno-admission-controller --type=json -p='[
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--imagePullSecrets=ecr-creds"}]' 2>/dev/null || true
kubectl -n kyverno rollout status deployment kyverno-admission-controller --timeout=120s

echo "==> policies"
kubectl apply -f policies/kyverno/
# Deploying before the policies are Ready races the webhook registration and the
# vulnerable image gets ADMITTED — the exact failure the demo exists to prevent.
kubectl wait --for=condition=Ready clusterpolicy --all --timeout=120s
kubectl get clusterpolicy

echo
echo "==> DEPLOY ATTEMPT (expect: DENIED — critical CVEs in the signed attestation)"
# The first verification on a cold cache can blow the 30s admission-webhook budget
# (ECR + Sigstore round-trips) and deny with an InternalError instead of the policy
# message. Still fail-closed, but retry so the demo shows the real denial.
for attempt in 1 2 3; do
  if out=$(kubectl apply -f k8s/deployment.yaml 2>&1); then
    echo "$out"
    echo "GATE FAILED: the vulnerable image was ADMITTED."
    exit 1
  fi
  echo "$out"
  case "$out" in
    *"blocked due to the following policies"*) echo "  ^ blocked as designed."; break ;;
    *) echo "  (webhook timed out before verification finished — retrying on warm cache)"; sleep 5 ;;
  esac
done
