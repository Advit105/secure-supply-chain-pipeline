variable "region" {
  description = "AWS region for the ECR repository"
  type        = string
  default     = "us-east-1"
}

variable "repository_name" {
  description = "ECR repository name"
  type        = string
  default     = "vulnerable-demo-app"
}

variable "github_repository" {
  # GitHub's OIDC sub claim embeds immutable owner/repo IDs on newer accounts
  # (owner@id/repo@id). Get yours by decoding a workflow token's sub claim.
  description = "GitHub owner@id/repo@id allowed to assume the CI role via OIDC"
  type        = string
  default     = "Advit105@149078227/secure-supply-chain-pipeline@1301808971"
}
