# DefectDojo (findings aggregation)

The upload happens in [`scripts/defectdojo-upload.sh`](../scripts/defectdojo-upload.sh),
called by the `defectdojo` CI job. To run DefectDojo itself, use the project's
official compose rather than a copy that would rot here:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
./dc-build.sh
./dc-up.sh                       # serves on http://localhost:8080
docker compose logs initializer | grep "Admin password"   # first-run creds
```

Then create an API token (User → API v2 Key) and export it so CI / the script can
push reports:

```bash
export DD_URL=http://localhost:8080
export DD_API_KEY=<token>
OUT_DIR=artifacts bash ../scripts/defectdojo-upload.sh
```

The script uses `import-scan` with `auto_create_context=true`, so the product
**"Supply Chain Pipeline"** and engagement **"CI"** are created on first import.
Scan types uploaded: Gitleaks, Semgrep, Trivy (fs + image), Checkov.
