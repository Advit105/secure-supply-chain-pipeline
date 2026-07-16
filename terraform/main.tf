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

resource "aws_ecr_repository" "app" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE" # signed tags can't be overwritten (CKV_AWS_51)

  image_scanning_configuration {
    scan_on_push = true # AWS-side scanning in addition to Trivy (CKV_AWS_163)
  }

  # ponytail: default AES256 instead of a KMS CMK — a CMK costs $1/mo and this
  # stays in the free tier. Checkov flags it (CKV_AWS_136), which doubles as a
  # live IaC finding flowing into DefectDojo. Add the CMK back if cost is fine.

  tags = {
    Project = "supply-chain-pipeline"
  }
}

# Keep storage under the 500 MB free-tier allowance: drop untagged layers fast
# and cap the total image count.
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep only the 5 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = { type = "expire" }
      }
    ]
  })
}
