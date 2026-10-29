variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Target deployment environment"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "Name of the EKS Zero-Trust cluster"
  type        = string
  default     = "prod-eks-zero-trust-mesh"
}

variable "kubernetes_version" {
  description = "Kubernetes control plane version"
  type        = string
  default     = "1.30"
}

variable "enable_eventbridge_quarantine" {
  description = "Whether to deploy the automated runtime pod quarantine pipeline"
  type        = bool
  default     = true
}
