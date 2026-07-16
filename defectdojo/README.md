# DefectDojo (findings aggregation)

Every scanner's report lands in one dashboard. The upload is
[`scripts/defectdojo-upload.sh`](../scripts/defectdojo-upload.sh); DefectDojo
itself runs from its official compose (a copy here would just rot).

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo

# macOS + Docker Desktop only: this file makes the initializer's bind-mount read
# deadlock ("Resource deadlock avoided"). It's optional; remove it.
rm -f docker/extra_settings/README.md

docker compose pull
docker compose up -d --no-build          # serves on http://localhost:8080
# admin password is auto-generated; read it once:
docker compose logs initializer | grep -i "password"
```

Get an API token and push the reports (from a directory holding the scan JSONs —
locally, run `make scan` first, or download them from a CI run's artifacts):

```bash
TOK=$(curl -s -X POST http://localhost:8080/api/v2/api-token-auth/ \
        -d "username=admin&password=<admin-pw>" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
DD_URL=http://localhost:8080 DD_API_KEY=$TOK OUT_DIR=artifacts \
  bash scripts/defectdojo-upload.sh
```

`import-scan` runs with `auto_create_context=true`, so first upload creates the
product type **DevSecOps**, product **Supply Chain Pipeline**, and engagement
**CI**. Scan types: Gitleaks, Semgrep, Trivy (fs + image), Checkov. A verified
run aggregated **17 Critical / 107 High / 131 Medium / 140 Low** across them.

> CI note: the pipeline's `defectdojo` job pushes automatically when the
> `DEFECTDOJO_URL` / `DEFECTDOJO_API_KEY` secrets are set — but a GitHub runner
> can't reach a DefectDojo on your laptop. Point those secrets at a reachable
> instance, or run the upload locally as above.
