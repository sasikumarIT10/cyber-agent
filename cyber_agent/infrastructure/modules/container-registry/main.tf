variable "project_name" {
  type    = string
  default = "cyber-agent"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "provider_type" {
  description = "Cloud provider: aws or gcp"
  type        = string
}

variable "region" {
  type = string
}

variable "gcp_project_id" {
  type    = string
  default = ""
}

# --- AWS ECR ---

resource "aws_ecr_repository" "main" {
  count = var.provider_type == "aws" ? 1 : 0

  name                 = "${var.project_name}/${var.environment}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_ecr_lifecycle_policy" "main" {
  count      = var.provider_type == "aws" ? 1 : 0
  repository = aws_ecr_repository.main[0].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 20 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 20
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Remove untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# --- GCP Artifact Registry ---

resource "google_artifact_registry_repository" "main" {
  count = var.provider_type == "gcp" ? 1 : 0

  location      = var.region
  repository_id = "${var.project_name}-${var.environment}"
  description   = "Container images for ${var.project_name}"
  format        = "DOCKER"
  project       = var.gcp_project_id

  cleanup_policies {
    id     = "keep-minimum-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s"
    }
  }
}

# --- Outputs ---

output "registry_url" {
  value = var.provider_type == "aws" ? (
    length(aws_ecr_repository.main) > 0 ? aws_ecr_repository.main[0].repository_url : ""
  ) : (
    length(google_artifact_registry_repository.main) > 0 ? "${var.region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.main[0].repository_id}" : ""
  )
}
