# Hardened multi-stage build. The npm dependencies are STILL the deliberately-old,
# vulnerable ones (that's the point of the demo — Kyverno must still have real CRITICALs
# to reject); what changed is the runtime image. The old single-stage bullseye base
# (app/Dockerfile.vulnerable) carried the entire Debian OS CVE surface; this runtime is
# Chainguard's node image, which is continuously rebuilt and currently ships ZERO OS CVEs.
# scripts/measure-cve-delta.sh prints the before/after count.
#
# Why Chainguard over gcr.io/distroless: at build time the debian-12 distroless bases still
# carried a fixable OpenSSL CRITICAL (CVE-2026-31789) that hadn't been rebuilt in yet, which
# (correctly) tripped the severity gate. Chainguard's rolling rebuilds ship the fix already.

# --- builder: full Node image, only used to resolve node_modules ---
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json ./
# npm install (not ci) keeps the intentionally-old resolved versions; no committed lockfile.
RUN npm install --omit=dev && npm cache clean --force

# --- runtime: Chainguard node, nonroot (uid 65532), no shell / no package manager ---
# ponytail: :latest is a moving tag (Chainguard's free tier only offers latest/latest-dev).
# For production, pin a digest or a paid semver tag so the runtime is reproducible.
FROM cgr.dev/chainguard/node:latest
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY server.js ./

EXPOSE 3000
# Exec form (JSON array) — the runtime has no /bin/sh for a shell-form HEALTHCHECK. In k8s
# the httpGet readinessProbe is what's used; this only matters for docker/compose runs.
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/bin/node", "-e", "require('http').get('http://127.0.0.1:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
# ENTRYPOINT is /usr/bin/node (from the base), so CMD is just the script path.
CMD ["server.js"]
