#!/usr/bin/env bash
# Generate an SBOM for the built image in both CycloneDX and SPDX.
# Usage: IMAGE=<ref> scripts/generate-sbom.sh   (or pass the ref as $1)
set -euo pipefail

IMAGE="${1:-${IMAGE:?set IMAGE to the image ref}}"
OUT="${OUT_DIR:-artifacts}"
mkdir -p "$OUT"

syft "$IMAGE" -o cyclonedx-json="$OUT/sbom.cdx.json"
syft "$IMAGE" -o spdx-json="$OUT/sbom.spdx.json"

echo "SBOM written to $OUT/sbom.cdx.json and $OUT/sbom.spdx.json"
