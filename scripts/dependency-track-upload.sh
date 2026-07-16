#!/usr/bin/env bash
# Push the CycloneDX SBOM into Dependency-Track for CONTINUOUS monitoring. Unlike a
# point-in-time scan, DT keeps the SBOM and re-checks it against new CVE feeds, so a
# vulnerability disclosed after deploy still surfaces against the shipped image.
#
# Env: DEPTRACK_URL (e.g. http://localhost:8081), DEPTRACK_API_KEY
# Reads the SBOM from $OUT_DIR (default: artifacts). Missing SBOM is skipped, not fatal.
set -euo pipefail

DT_URL="${DEPTRACK_URL:?set DEPTRACK_URL}"
DT_KEY="${DEPTRACK_API_KEY:?set DEPTRACK_API_KEY}"
OUT="${OUT_DIR:-artifacts}"
PROJECT="${DT_PROJECT:-vulnerable-demo-app}"
VERSION="${DT_VERSION:-${GITHUB_SHA:-local}}"
SBOM="$OUT/sbom.cdx.json"

[ -s "$SBOM" ] || { echo "skip (missing/empty): $SBOM"; exit 0; }

echo "uploading $SBOM to Dependency-Track project '$PROJECT' version '$VERSION'"
# autoCreate=true makes DT create the project on first upload; every later run adds a
# new version, giving you a history of the SBOM across builds.
curl -sf -X POST "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_KEY" \
  -F "projectName=$PROJECT" \
  -F "projectVersion=$VERSION" \
  -F "autoCreate=true" \
  -F "bom=@$SBOM" >/dev/null && echo "  ok"
echo "Dependency-Track upload complete: $DT_URL"
