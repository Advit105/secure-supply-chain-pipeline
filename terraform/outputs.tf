output "repository_url" {
  description = "ECR repository URL used by the CI push step"
  value       = aws_ecr_repository.app.repository_url
}

output "repository_arn" {
  value = aws_ecr_repository.app.arn
}

output "github_actions_role_arn" {
  description = "Paste this as the AWS_ROLE_ARN secret in the GitHub repo"
  value       = aws_iam_role.github_actions.arn
}
