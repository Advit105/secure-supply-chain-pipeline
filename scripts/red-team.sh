#!/usr/bin/env bash
# Red-team the pipeline: for each control, run the attack that SHOULD be blocked and
# assert it actually is. Self-verifying — every check either proves a control works or
# fails the script. This backs the claims in docs/red-team.md with runnable evidence.
#
# Scope: the checks that don't need cloud infra run anywhere (secret detection, waiver
# expiry, VEX strictness, provenance content). The admission-gate checks need a running
# k3d cluster with Kyverno + policies applied (scripts/demo-cluster.sh); they auto-skip
# with a clear message if kubectl can't reach a cluster, so the script is useful locally
# and exhaustive in the demo environment.
#
# Usage: scripts/red-team.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }
skip() { echo "  SKIP: $1"; }

echo "== CICD-SEC-6 Insufficient Credential Hygiene — gitleaks catches a committed secret =="
# Attack: commit a fake AWS key; the gitleaks config must flag it.
tmp="$(mktemp)"; printf 'aws_secret_access_key = "AKIAIOSFODNN7EXAMPLE"\nkey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n' > "$tmp"
if command -v gitleaks >/dev/null 2>&1; then GL="gitleaks detect --no-git --source $tmp"; else
  GL="docker run --rm -v $tmp:/f zricethezav/gitleaks:v8.18.4 detect --no-git --source /f"; fi
if $GL >/dev/null 2>&1; then bad "gitleaks did NOT flag a committed AWS key"; else ok "committed secret blocked by gitleaks"; fi
rm -f "$tmp"

echo "== CICD-SEC-1 Insufficient Flow Control — expired security waivers break the build =="
# Attack: sneak in a waiver whose date has already passed; check-waivers.sh must fail.
tmp="$(mktemp)"; printf 'vulnerabilities:\n  - id: CVE-0000-9999\n    expired_at: 2000-01-01\n' > "$tmp"
if bash scripts/check-waivers.sh "$tmp" >/dev/null 2>&1; then bad "expired waiver was NOT caught"; else ok "expired waiver breaks the build"; fi
rm -f "$tmp"

echo "== CICD-SEC-9 Artifact Integrity — VEX must not weaken the admission scan =="
# The Kyverno vuln attestation is produced WITHOUT --vex (grep sign-and-attest.sh). If a
# future edit added --vex to the vuln predicate, the gate could be silenced. Assert it's absent.
if grep -q 'cosign-vuln' scripts/sign-and-attest.sh && ! grep -E 'trivy image .*cosign-vuln.*--vex|--vex.*cosign-vuln' scripts/sign-and-attest.sh >/dev/null 2>&1; then
  ok "gate's vuln attestation is computed WITHOUT VEX (stays strict)"
else bad "VEX may be suppressing the admission gate's vuln scan"; fi

echo "== CICD-SEC-4 Poisoned Pipeline Execution — provenance names THIS repo, not an attacker's =="
# The provenance predicate + policy must bind the build to our repository.
if grep -q 'Advit105/secure-supply-chain-pipeline' policies/kyverno/verify-provenance.yaml \
   && grep -q 'buildDefinition.externalParameters.workflow.repository' policies/kyverno/verify-provenance.yaml; then
  ok "provenance policy pins the source repository"
else bad "provenance policy does not bind to the source repo"; fi

echo "== Admission gate (needs k3d + Kyverno) =="
if ! command -v kubectl >/dev/null 2>&1 || ! kubectl cluster-info >/dev/null 2>&1; then
  skip "no reachable cluster — run scripts/demo-cluster.sh to exercise Kyverno gates"
else
  # Attack 1: unsigned/never-attested public image must be denied in the demo namespace.
  if kubectl -n demo run rt-unsigned --image=nginx:latest --dry-run=server >/dev/null 2>&1; then
    bad "an unsigned image was admitted to ns/demo"
  else ok "unsigned image denied at admission"; fi
  # Attack 2: the intentionally-vulnerable demo image (critical CVEs) must be denied.
  img="$(grep -oE '[0-9]+\.dkr\.ecr\.[^ ]+vulnerable-demo-app@sha256:[a-f0-9]+' k8s/deployment.yaml | head -1)"
  if [ -n "$img" ] && kubectl -n demo run rt-vuln --image="$img" --dry-run=server >/dev/null 2>&1; then
    bad "a critical-laden image was admitted to ns/demo"
  elif [ -n "$img" ]; then ok "critical-vulnerability image denied at admission"; else skip "no digest-pinned image in k8s/deployment.yaml"; fi
fi

echo
echo "red-team summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
