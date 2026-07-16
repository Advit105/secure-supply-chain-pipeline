#!/usr/bin/env bash
# Keyless-sign the image and attach three attestations Kyverno later verifies:
#   1. the SBOM (CycloneDX)         -> provenance of what's inside
#   2. the Trivy vulnerability scan -> lets admission block critical CVEs
#   3. SLSA build provenance (v1)   -> lets admission verify WHERE it was built
#                                      (this repo, this workflow, this commit)
#
# Keyless (Fulcio + Rekor) needs an OIDC token; in GitHub Actions that's the
# ambient workflow identity (id-token: write). Locally, `cosign` opens a browser.
# Usage: IMAGE=<ref-by-digest> scripts/sign-and-attest.sh
set -euo pipefail

IMAGE="${1:-${IMAGE:?set IMAGE to the image ref (use the immutable digest, not a tag)}}"
OUT="${OUT_DIR:-artifacts}"
export COSIGN_EXPERIMENTAL=1

# 1. Sign.
cosign sign --yes "$IMAGE"

# 2. SBOM attestation (generate if the SBOM step didn't already).
[ -f "$OUT/sbom.cdx.json" ] || syft "$IMAGE" -o cyclonedx-json="$OUT/sbom.cdx.json"
cosign attest --yes --type cyclonedx --predicate "$OUT/sbom.cdx.json" "$IMAGE"

# 3. Vulnerability attestation from Trivy (predicate type the Kyverno policy checks).
trivy image --format cosign-vuln --output "$OUT/trivy.cosign.json" "$IMAGE"
cosign attest --yes --type vuln --predicate "$OUT/trivy.cosign.json" "$IMAGE"

# 4. SLSA v1 build provenance. Built from the ambient GitHub Actions context so
# Kyverno can later assert the image came from THIS repo + workflow + commit, not
# just that it's signed. Fallbacks keep local runs from crashing (they produce a
# provenance marked local/unknown, which the admission policy would reject — as it
# should, since a laptop build has no trusted builder identity).
SERVER="${GITHUB_SERVER_URL:-https://github.com}"
REPO="${GITHUB_REPOSITORY:-local/unknown}"
REF="${GITHUB_REF:-refs/heads/local}"
COMMIT="${GITHUB_SHA:-0000000000000000000000000000000000000000}"
WF_REF="${GITHUB_WORKFLOW_REF:-$REPO/.github/workflows/pipeline.yml@$REF}"
RUN_ID="${GITHUB_RUN_ID:-0}"
cat > "$OUT/provenance.slsa.json" <<EOF
{
  "buildDefinition": {
    "buildType": "https://github.com/actions/runner/github-hosted",
    "externalParameters": {
      "workflow": {
        "ref": "$REF",
        "repository": "$SERVER/$REPO",
        "path": ".github/workflows/pipeline.yml"
      }
    },
    "internalParameters": { "github": { "run_id": "$RUN_ID" } },
    "resolvedDependencies": [
      { "uri": "git+$SERVER/$REPO@$REF", "digest": { "gitCommit": "$COMMIT" } }
    ]
  },
  "runDetails": {
    "builder": { "id": "$SERVER/$WF_REF" },
    "metadata": {
      "invocationId": "$SERVER/$REPO/actions/runs/$RUN_ID",
      "startedOn": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
  }
}
EOF
cosign attest --yes --type slsaprovenance1 --predicate "$OUT/provenance.slsa.json" "$IMAGE"

echo "Signed + attested (sbom, vuln, slsa-provenance): $IMAGE"
