variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "github_repository" {
  description = "owner/repo allowed to deploy."
  type        = string
}

variable "github_environment" {
  description = "GitHub environment the deploy job must run in."
  type        = string
  default     = "production"
}

variable "create_oidc_provider" {
  description = "Create the account-wide GitHub OIDC provider (only one may exist per account)."
  type        = bool
  default     = true
}

variable "ecr_repository_arn" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "service_name" {
  type = string
}

variable "pass_role_arns" {
  description = "Task and execution role ARNs the deploy job may pass to ECS."
  type        = list(string)
}
