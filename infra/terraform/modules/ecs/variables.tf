variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "app_subnet_ids" {
  type = list(string)
}

variable "app_security_group_id" {
  description = "Security group attached to the API tasks (created by the caller, shared with RDS/cache rules)."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate for the HTTPS listener."
  type        = string
}

variable "image" {
  description = "Container image (ECR URL with an immutable tag, e.g. the git SHA)."
  type        = string
}

variable "ecr_repository_arn" {
  type = string
}

variable "task_role_arn" {
  type = string
}

variable "task_role_name" {
  type = string
}

variable "bucket_name" {
  type = string
}

variable "bucket_arn" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "secret_arns" {
  description = "Env var name => Secrets Manager ARN, injected into the container."
  type        = map(string)
}

variable "log_group_name" {
  type = string
}

variable "log_group_arn" {
  type = string
}

variable "log_bucket_name" {
  description = "Bucket for ALB access logs."
  type        = string
}

variable "cors_allowed_origins" {
  type    = list(string)
  default = []
}

variable "extra_environment" {
  type    = map(string)
  default = {}
}

variable "cpu" {
  type    = number
  default = 512
}

variable "memory" {
  type    = number
  default = 1024
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "max_count" {
  type    = number
  default = 6
}

variable "deletion_protection" {
  type    = bool
  default = true
}
