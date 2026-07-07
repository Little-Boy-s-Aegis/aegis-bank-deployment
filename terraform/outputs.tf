output "eks_cluster_name" {
  description = "EKS Cluster Name"
  value       = aws_eks_cluster.cluster.name
}

output "eks_endpoint" {
  description = "EKS Cluster Control Plane Endpoint"
  value       = aws_eks_cluster.cluster.endpoint
}

output "rds_endpoint" {
  description = "PostgreSQL RDS connection endpoint"
  value       = aws_db_instance.postgres.address
}

output "redis_endpoint" {
  description = "Redis Cache node connection endpoint"
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "msk_bootstrap_brokers" {
  description = "Kafka brokers bootstrap endpoints"
  value       = aws_msk_cluster.kafka.bootstrap_brokers
}

output "s3_log_bucket" {
  description = "S3 compliance log bucket"
  value       = aws_s3_bucket.logs.id
}

output "kubeconfig_update_command" {
  description = "Command to update local kubeconfig for EKS access"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.cluster.name}"
}
