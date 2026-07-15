#!/usr/bin/env bash
# Keyless-sign the image and attach two attestations Kyverno later verifies:
#   1. the SBOM (CycloneDX)         -> provenance of what's inside
#   2. the Trivy vulnerability scan -> lets admission block critical CVEs
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

echo "Signed + attested (sbom, vuln): $IMAGE"
