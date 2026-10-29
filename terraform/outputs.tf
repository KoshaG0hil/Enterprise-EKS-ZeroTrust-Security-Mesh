output "cluster_name" {
  description = "The name of the EKS Zero-Trust cluster"
  value       = aws_eks_cluster.mesh_cluster.name
}

output "cluster_arn" {
  description = "The ARN of the EKS Zero-Trust cluster"
  value       = aws_eks_cluster.mesh_cluster.arn
}

output "cluster_endpoint" {
  description = "The endpoint URL for the Kubernetes API server"
  value       = aws_eks_cluster.mesh_cluster.endpoint
}

output "kms_secrets_key_arn" {
  description = "ARN of KMS key used for Kubernetes secrets envelope encryption"
  value       = aws_kms_key.eks_secrets.arn
}

output "quarantine_lambda_arn" {
  description = "ARN of the automated Falco pod quarantine Lambda function"
  value       = aws_lambda_function.falco_pod_quarantine.arn
}

output "falco_eventbridge_rule_arn" {
  description = "ARN of EventBridge rule capturing Falco runtime threat events"
  value       = aws_cloudwatch_event_rule.falco_threat_rule.arn
}
