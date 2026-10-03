variable "name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  description = "Application/audit log retention. One year supports incident investigations."
  type        = number
  default     = 365
}

variable "alarm_email" {
  description = "Optional email address subscribed to alarm notifications."
  type        = string
  default     = null
}

variable "alb_arn_suffix" {
  type = string
}

variable "target_group_arn_suffix" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "service_name" {
  type = string
}

variable "db_instance_id" {
  type = string
}
