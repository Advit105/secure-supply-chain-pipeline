output "repository_url" {
  description = "ECR repository URL used by the CI push step"
  value       = aws_ecr_repository.app.repository_url
}

output "repository_arn" {
  value = aws_ecr_repository.app.arn
}
