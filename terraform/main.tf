terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "EKS-ZeroTrust-Security-Mesh"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "SecOps-Platform"
      Repository  = "https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh"
    }
  }
}

locals {
  name_prefix = "${var.cluster_name}-${var.environment}"
  common_tags = {
    MeshType   = "ZeroTrust-eBPF"
    Compliance = "CIS-EKS-v1.4.0"
    RuntimeSec = "Falco-Cilium-Gatekeeper"
  }
}
