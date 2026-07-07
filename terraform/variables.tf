variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "aegis-security-cluster"
}

variable "db_password" {
  description = "Password for PostgreSQL Master DB User"
  type        = string
  sensitive   = true
  default     = "aegisSecureProdPassword1234"
}
