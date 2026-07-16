#!/usr/bin/env bash
# Push pipeline security metrics to a Prometheus Pushgateway so Grafana can chart them over
# time. Each CI run overwrites the group; Prometheus samples the trajectory. Best-effort:
# no PUSHGATEWAY_URL => no-op (like the DefectDojo/Dependency-Track uploads).
#
# Env: PUSHGATEWAY_URL, OUT_DIR (default artifacts), GATE_RESULT (1 pass / 0 fail, default 1)
set -euo pipefail
PGW="${PUSHGATEWAY_URL:-}"
[ -n "$PGW" ] || { echo "no PUSHGATEWAY_URL; skipping metrics push"; exit 0; }
OUT="${OUT_DIR:-artifacts}"
GATE_RESULT="${GATE_RESULT:-1}"
SCAN="$OUT/trivy-image.json"

count() { # $1 = CRITICAL|HIGH|MEDIUM|LOW -> integer count from the image scan (0 if no file)
  [ -s "$SCAN" ] || { echo 0; return; }
  python3 -c "import json;d=json.load(open('$SCAN'));print(sum(1 for r in d.get('Results',[]) for v in (r.get('Vulnerabilities') or []) if v['Severity']=='$1'))"
}

# Pushgateway consumes the Prometheus text exposition format on the request body.
curl -sf --data-binary @- "$PGW/metrics/job/security-pipeline" <<EOF && echo "pushed metrics to $PGW"
# TYPE demo_image_vulnerabilities gauge
demo_image_vulnerabilities{severity="critical"} $(count CRITICAL)
demo_image_vulnerabilities{severity="high"} $(count HIGH)
demo_image_vulnerabilities{severity="medium"} $(count MEDIUM)
demo_image_vulnerabilities{severity="low"} $(count LOW)
# TYPE pipeline_gate_result gauge
pipeline_gate_result $GATE_RESULT
# TYPE pipeline_last_run_timestamp_seconds gauge
pipeline_last_run_timestamp_seconds $(date +%s)
EOF
