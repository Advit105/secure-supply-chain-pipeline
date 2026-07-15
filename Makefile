# Local driver for the pipeline. CI (.github/workflows/pipeline.yml) runs the
# same steps. Requires: gitleaks, semgrep, checkov, trivy, syft, cosign, docker.
IMAGE ?= vulnerable-demo-app:local
OUT   ?= artifacts

.PHONY: hooks scan build image-scan sbom sign defectdojo policies deploy clean

hooks:            ## install the gitleaks pre-commit hook
	pre-commit install

scan: ## run all scanners into $(OUT)/ (report-only, never fails)
	@mkdir -p $(OUT)
	gitleaks detect --config .gitleaks.toml --report-format json --report-path $(OUT)/gitleaks.json --exit-code 0 || true
	semgrep --config semgrep/rules.yaml --config p/default --config p/nodejs --json --output $(OUT)/semgrep.json app/ || true
	checkov --config-file .checkov.yaml -o json > $(OUT)/checkov.json || true
	npm install --prefix app --package-lock-only
	trivy fs app --format json --output $(OUT)/trivy-fs.json --severity CRITICAL,HIGH || true
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

clean:
	rm -rf $(OUT) app/node_modules app/package-lock.json
