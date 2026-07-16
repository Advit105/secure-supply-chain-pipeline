# Local driver for the pipeline. CI (.github/workflows/pipeline.yml) runs the
# same steps. Requires: gitleaks, semgrep, checkov, trivy, syft, cosign, docker.
IMAGE ?= vulnerable-demo-app:local
OUT   ?= artifacts

.PHONY: hooks scan build image-scan sbom sign defectdojo policies deploy clean \
        waivers severity-gate cve-delta red-team ai-triage dependency-track monitoring

hooks:            ## install the gitleaks pre-commit hook
	pre-commit install

scan: ## run all scanners into $(OUT)/ (report-only, never fails)
	@mkdir -p $(OUT)
	gitleaks detect --config .gitleaks.toml --report-format json --report-path $(OUT)/gitleaks.json --exit-code 0 || true
	semgrep --config semgrep/rules.yaml --config p/default --config p/nodejs --json --output $(OUT)/semgrep.json app/ || true
	checkov --config-file .checkov.yaml -o json > $(OUT)/checkov.json || true
	npm install --prefix app --package-lock-only
	trivy fs app --format json --output $(OUT)/trivy-fs.json --severity CRITICAL,HIGH --vex vex/vulnerable-demo-app.openvex.json || true
	@echo "reports in $(OUT)/"

build:
	docker build -t $(IMAGE) app/

image-scan:
	trivy image $(IMAGE) --format json --output $(OUT)/trivy-image.json || true

sbom:
	IMAGE=$(IMAGE) OUT_DIR=$(OUT) bash scripts/generate-sbom.sh

sign: ## sign + attest (needs an OIDC identity; opens a browser locally)
	IMAGE=$(IMAGE) OUT_DIR=$(OUT) bash scripts/sign-and-attest.sh

defectdojo: ## push $(OUT)/ reports to DefectDojo (needs DD_URL, DD_API_KEY)
	OUT_DIR=$(OUT) bash scripts/defectdojo-upload.sh

policies: ## apply the Kyverno admission policies (needs a cluster + Kyverno)
	kubectl apply -f policies/kyverno/

deploy: ## register the ArgoCD app (GitOps takes over from there)
	kubectl apply -f argocd/application.yaml

waivers: ## fail if any .trivyignore.yaml waiver has expired
	bash scripts/check-waivers.sh

severity-gate: waivers ## HARD-fail on un-waived fixable CRITICAL in $(IMAGE)
	trivy image $(IMAGE) --severity CRITICAL --ignore-unfixed --exit-code 1 --ignorefile .trivyignore.yaml

cve-delta: ## print the before/after container CVE count (baseline vs hardened)
	bash scripts/measure-cve-delta.sh

red-team: ## run the pipeline's attacks and assert each is blocked
	bash scripts/red-team.sh

ai-triage: ## AI-prioritize $(OUT)/ findings (needs ANTHROPIC_API_KEY)
	OUT_DIR=$(OUT) node scripts/ai-triage.mjs

dependency-track: ## upload the SBOM to Dependency-Track (needs DEPTRACK_URL, DEPTRACK_API_KEY)
	OUT_DIR=$(OUT) bash scripts/dependency-track-upload.sh

monitoring: ## deploy Dependency-Track + Prometheus/Grafana into the cluster
	kubectl apply -k k8s/dependency-track
	kubectl apply -k k8s/monitoring

clean:
	rm -rf $(OUT) app/node_modules app/package-lock.json
