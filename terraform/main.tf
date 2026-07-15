terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# KMS key so the ECR repo is encrypted with a CMK (Checkov CKV_AWS_51 / CKV_AWS_136).
resource "aws_kms_key" "ecr" {
  description             = "CMK for ${var.repository_name} ECR encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_ecr_repository" "app" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE" # signed tags can't be overwritten (CKV_AWS_51)

  image_scanning_configuration {
    scan_on_push = true # AWS-side scanning in addition to Trivy (CKV_AWS_163)
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  tags = {
    Project = "supply-chain-pipeline"
  }
}

# Expire untagged images so the registry doesn't accumulate unsigned junk.
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 14
      }
      action = { type = "expire" }
    }]
  })
}
