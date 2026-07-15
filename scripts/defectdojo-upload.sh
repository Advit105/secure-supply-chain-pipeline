#!/usr/bin/env bash
# Push every scanner's report into DefectDojo. Uses import-scan with
# auto_create_context=true so the product/engagement are created on first run.
#
# Env: DD_URL (e.g. http://localhost:8080), DD_API_KEY
# Reads reports from $OUT_DIR (default: artifacts). Missing files are skipped.
set -euo pipefail

DD_URL="${DD_URL:?set DD_URL}"
DD_API_KEY="${DD_API_KEY:?set DD_API_KEY}"
OUT="${OUT_DIR:-artifacts}"
PRODUCT="${DD_PRODUCT:-Supply Chain Pipeline}"
ENGAGEMENT="${DD_ENGAGEMENT:-CI}"

# report file  ->  DefectDojo scan_type (exact strings DefectDojo expects)
declare -A SCANS=(
  ["$OUT/gitleaks.json"]="Gitleaks Scan"
  ["$OUT/semgrep.json"]="Semgrep JSON Report"
  ["$OUT/trivy-fs.json"]="Trivy Scan"
  ["$OUT/trivy-image.json"]="Trivy Scan"
  ["$OUT/checkov.json"]="Checkov Scan"
)

upload() {
  local file="$1" scan_type="$2"
  [ -s "$file" ] || { echo "skip (missing/empty): $file"; return; }
  echo "importing $file as '$scan_type'"
  curl -sf -X POST "$DD_URL/api/v2/import-scan/" \
    -H "Authorization: Token $DD_API_KEY" \
    -F "scan_type=$scan_type" \
    -F "file=@$file" \
    -F "product_name=$PRODUCT" \
    -F "engagement_name=$ENGAGEMENT" \
    -F "auto_create_context=true" \
    -F "active=true" -F "verified=false" \
    -F "minimum_severity=Low" >/dev/null && echo "  ok"
}

for file in "${!SCANS[@]}"; do
  upload "$file" "${SCANS[$file]}"
done
echo "DefectDojo import complete: $DD_URL"
