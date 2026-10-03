variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "region" {
  description = "AWS region (used for VPC endpoint service names)."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR."
  type        = string
  default     = "10.40.0.0/16"
}

variable "enable_nat_gateway" {
  description = "Give app subnets outbound internet access via NAT (not needed if every dependency has a VPC endpoint)."
  type        = bool
  default     = true
}

variable "one_nat_gateway_per_az" {
  description = "One NAT per AZ (HA) instead of a single shared NAT (cheaper)."
  type        = bool
  default     = false
}

variable "interface_endpoints" {
  description = "Interface VPC endpoints to create in the app subnets."
  type        = list(string)
  default     = ["ecr.api", "ecr.dkr", "logs", "secretsmanager", "kms", "sts"]
}

variable "flow_logs_bucket_arn" {
  description = "S3 bucket ARN for VPC flow logs (null to disable)."
  type        = string
  default     = null
}
