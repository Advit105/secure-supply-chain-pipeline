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
PRODUCT_TYPE="${DD_PRODUCT_TYPE:-DevSecOps}" # required to auto-create the product
ENGAGEMENT="${DD_ENGAGEMENT:-CI}"

# report file | DefectDojo scan_type (exact strings DefectDojo expects).
# Plain string pairs, not an associative array, so this runs on macOS's bash 3.2.
SCANS="gitleaks.json|Gitleaks Scan
semgrep.json|Semgrep JSON Report
trivy-fs.json|Trivy Scan
trivy-image.json|Trivy Scan
checkov.json|Checkov Scan"

upload() {
  local file="$1" scan_type="$2"
  [ -s "$file" ] || { echo "skip (missing/empty): $file"; return; }
  echo "importing $file as '$scan_type'"
  curl -sf -X POST "$DD_URL/api/v2/import-scan/" \
    -H "Authorization: Token $DD_API_KEY" \
    -F "scan_type=$scan_type" \
    -F "file=@$file" \
    -F "product_name=$PRODUCT" \
    -F "product_type_name=$PRODUCT_TYPE" \
    -F "engagement_name=$ENGAGEMENT" \
    -F "auto_create_context=true" \
    -F "active=true" -F "verified=false" \
    -F "minimum_severity=Low" >/dev/null && echo "  ok"
}

printf '%s\n' "$SCANS" | while IFS='|' read -r fname stype; do
  [ -n "$fname" ] && upload "$OUT/$fname" "$stype"
done
echo "DefectDojo import complete: $DD_URL"
