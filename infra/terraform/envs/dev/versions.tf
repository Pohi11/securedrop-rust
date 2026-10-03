terraform {
  # 1.11+: ephemeral resources and write-only arguments keep secrets out of state.
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # Remote state in S3 with native S3 locking (`use_lockfile`; no DynamoDB table needed).
  # Values are supplied at init time so this file holds no account-specific data:
  #   terraform init -backend-config=backend.hcl
  # See backend.hcl.example and ../../bootstrap.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  # Every resource gets these tags: cost allocation, ownership, and "who created this?"
  default_tags {
    tags = {
      Project     = "securedrop"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
