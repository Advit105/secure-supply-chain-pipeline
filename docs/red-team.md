# Red-teaming the pipeline

Every control in this project earns its place by stopping a specific attack. This document
lists those attacks, the control that blocks each one, and maps them to the
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

The claims here are not aspirational — [`scripts/red-team.sh`](../scripts/red-team.sh) runs the
attacks and asserts each is blocked. The checks that need no cloud infra run anywhere; the
admission-gate checks run against a local k3d cluster ([`scripts/demo-cluster.sh`](../scripts/demo-cluster.sh)).

```
$ scripts/red-team.sh
  PASS: committed secret blocked by gitleaks
  PASS: expired waiver breaks the build
  PASS: gate's vuln attestation is computed WITHOUT VEX (stays strict)
  PASS: provenance policy pins the source repository
  PASS: unsigned image denied at admission          # with cluster up
  PASS: critical-vulnerability image denied at admission
```

## Attack → control matrix

| # | Attack | Control that blocks it | OWASP CI/CD |
|---|--------|------------------------|-------------|
| 1 | Commit an AWS secret key | gitleaks (pre-commit + CI) with a custom rule | CICD-SEC-6 Insufficient Credential Hygiene |
| 2 | Sneak in a vulnerable dependency with a fix available | CI severity gate fails on un-waived fixable CRITICAL | CICD-SEC-3 Dependency Chain Abuse |
| 3 | Let a "temporary" waiver quietly become permanent | `check-waivers.sh` fails the build once `expired_at` passes | CICD-SEC-1 Insufficient Flow Control |
| 4 | Push an unsigned image and deploy it | Kyverno `verify-image-signature` (keyless cosign) denies it | CICD-SEC-9 Improper Artifact Integrity Validation |
| 5 | Deploy an image built from a different (attacker) repo | Kyverno `verify-build-provenance` checks the SLSA provenance names THIS repo | CICD-SEC-4 Poisoned Pipeline Execution |
| 6 | Deploy an image with critical CVEs | Kyverno `block-critical-vulnerabilities` reads the vuln attestation and denies | CICD-SEC-3 / CICD-SEC-9 |
| 7 | Silence the admission gate by adding VEX to its scan | The vuln attestation is computed WITHOUT `--vex`; VEX only filters report-only scans | CICD-SEC-9 |
| 8 | Steal long-lived AWS keys from CI | There are none — CI assumes an IAM role via GitHub OIDC | CICD-SEC-6 |

## The attacks in detail

### 1. Committed secret (CICD-SEC-6)
**Attack:** a developer commits `aws_secret_access_key = "…"`.
**Control:** gitleaks runs as a pre-commit hook and again in CI. The custom rule in
`.gitleaks.toml` also flags the app's hardcoded JWT signing secret.
**Observed:** the commit / CI job reports the leak. `red-team.sh` feeds a fake AWS key to
gitleaks and asserts a non-zero (leak-found) exit.

### 2. Vulnerable dependency with a fix (CICD-SEC-3)
**Attack:** bump a dependency to a version with a known, fixable CRITICAL.
**Control:** the `severity-gate` job runs `trivy image --severity CRITICAL --ignore-unfixed
--exit-code 1` and stops the build **before** the image is pushed. The demo's intentional
criticals are the only exceptions, and each is an explicit, dated waiver in `.trivyignore.yaml`.
**Observed:** an un-waived fixable critical turns the gate red; nothing is signed or pushed.

### 3. The permanent "temporary" exception (CICD-SEC-1)
**Attack:** waive a finding "just for now" and never revisit it.
**Control:** every waiver carries an `expired_at`. `check-waivers.sh` fails the build the
moment a waiver lapses, forcing a renewal decision or a fix — exceptions can't rot silently.
**Observed:** `red-team.sh` plants a waiver dated 2000-01-01 and asserts the check fails.

### 4. Unsigned image (CICD-SEC-9)
**Attack:** push any image (or a public one) and try to run it in `ns/demo`.
**Control:** Kyverno `verify-image-signature` requires a keyless cosign signature from our
exact workflow identity (Fulcio issuer + `subject` = this repo's `pipeline.yml@refs/heads/main`,
verified against Rekor). No signature → denied at admission.
**Observed:** `kubectl -n demo run --image=nginx:latest` is rejected by the webhook.

### 5. Wrong-repo provenance (CICD-SEC-4)
**Attack:** an attacker with signing access builds the image from *their* fork and tries to
pass it off as ours.
**Control:** `verify-build-provenance` doesn't just check that a SLSA provenance attestation
exists — it asserts `buildDefinition.externalParameters.workflow.repository` equals our repo
and the build ran on a GitHub-hosted runner. Provenance that names a different repo is denied.
This is the "built from THIS repo, THIS workflow" guarantee, not merely "is it signed."
**Observed:** the policy file pins the repository; `red-team.sh` asserts that binding is present.

### 6. Critical-CVE image (CICD-SEC-3 / 9)
**Attack:** ship the intentionally-vulnerable demo image (it still carries critical CVEs in
its old npm dependencies even after the base image was hardened).
**Control:** `block-critical-vulnerabilities` reads the cosign vuln attestation (Trivy output)
and denies admission if it reports any CRITICAL. CI happily builds, signs, and pushes it — the
**cluster** is what refuses it.
**Observed:** deploying the digest pinned in `k8s/deployment.yaml` is denied.

### 7. Silencing the gate with VEX (CICD-SEC-9)
**Attack:** add `--vex` to the gate's Trivy scan so waived/triaged CVEs disappear from the
attestation and the gate passes.
**Control:** by design, VEX (`vex/…openvex.json`) is applied **only** to the report-only
visibility scans. The attestation that feeds Kyverno is produced strictly, without VEX, in
`sign-and-attest.sh`.
**Observed:** `red-team.sh` greps `sign-and-attest.sh` and fails if VEX ever touches the vuln
predicate.

### 8. Stealing CI cloud credentials (CICD-SEC-6)
**Attack:** exfiltrate `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` from CI secrets.
**Control:** there are none to steal. CI federates into AWS via GitHub OIDC, assuming an IAM
role scoped to `ref:refs/heads/main` with ECR-push-only permissions. Tokens are short-lived
and branch-bound.
**Observed:** the workflow references only `AWS_ROLE_ARN`; no static AWS keys exist in the repo
or its secrets.

## Not yet covered (honest gaps)

- **CICD-SEC-2 (IAM) / CICD-SEC-5 (PBAC):** branch protection and required-reviewers are GitHub
  settings, documented but not enforced by code here.
- **CICD-SEC-10 (Logging/Visibility):** findings flow to DefectDojo + Dependency-Track and
  metrics to Grafana, but there's no tamper-evident audit log of pipeline actions themselves.
