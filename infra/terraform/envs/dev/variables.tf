variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "enable_nat_gateway" {
  type    = bool
  default = true
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the API's HTTPS listener."
  type        = string
}

variable "image_tag" {
  description = "Image tag to deploy initially (CI/CD updates it afterwards)."
  type        = string
  default     = "bootstrap"
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "cors_allowed_origins" {
  type    = list(string)
  default = []
}

variable "enable_waf" {
  type    = bool
  default = true
}

variable "enable_malware_protection" {
  type    = bool
  default = true
}

variable "db_multi_az" {
  type    = bool
  default = false
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "alarm_email" {
  type    = string
  default = null
}

variable "github_repository" {
  description = "owner/repo allowed to deploy via GitHub Actions OIDC (null = no CI role)."
  type        = string
  default     = null
}

variable "create_github_oidc_provider" {
  type    = bool
  default = true
}
