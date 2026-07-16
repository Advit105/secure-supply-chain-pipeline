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
  description = "GitHub org/repo allowed to assume the CI role via OIDC"
  type        = string
  default     = "Advit105/secure-supply-chain-pipeline"
}
