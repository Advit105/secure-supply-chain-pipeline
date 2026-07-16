#!/usr/bin/env bash
# Fail if any waiver in .trivyignore.yaml has passed its expired_at date. This is what
# stops "temporary" security exceptions from silently becoming permanent: once a waiver
# lapses the build breaks until someone renews the date or fixes the finding.
#
# Usage:  scripts/check-waivers.sh [file]   (default: .trivyignore.yaml)
#         scripts/check-waivers.sh --self-test
# Date compare is done on YYYYMMDD integers so it works on macOS bash 3.2 and Linux alike
# (no `date -d`, which BSD date lacks).
set -euo pipefail

check_file() {
  local file="$1"
  [ -f "$file" ] || { echo "no waiver file ($file); nothing to check"; return 0; }
  local today expired=0 d cmp
  today="$(date -u +%Y%m%d)"
  while read -r d; do
    cmp="${d//-/}"
    if [ "$cmp" -lt "$today" ]; then
      echo "EXPIRED waiver: expired_at $d"
      expired=$((expired + 1))
    fi
  done < <(grep -E 'expired_at' "$file" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
  if [ "$expired" -gt 0 ]; then
    echo "FAIL: $expired expired waiver(s) in $file. Renew the date or remediate the finding."
    return 1
  fi
  echo "OK: all waivers in $file are current."
  return 0
}

self_test() {
  local tmp; tmp="$(mktemp)"
  # Past date -> must fail (exit 1).
  printf 'vulnerabilities:\n  - id: CVE-0000-0001\n    expired_at: 2000-01-01\n' > "$tmp"
  if check_file "$tmp" >/dev/null 2>&1; then echo "self-test FAIL: expired waiver not caught"; rm -f "$tmp"; exit 1; fi
  # Future date -> must pass (exit 0).
  printf 'vulnerabilities:\n  - id: CVE-0000-0002\n    expired_at: 2999-12-31\n' > "$tmp"
  if ! check_file "$tmp" >/dev/null 2>&1; then echo "self-test FAIL: current waiver wrongly rejected"; rm -f "$tmp"; exit 1; fi
  rm -f "$tmp"
  echo "self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
else
  check_file "${1:-.trivyignore.yaml}"
fi
