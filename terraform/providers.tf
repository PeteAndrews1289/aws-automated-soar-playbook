terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "2.8.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "6.55.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}
