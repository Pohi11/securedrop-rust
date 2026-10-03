variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "kms_key_arn" {
  description = "CMK used for default bucket encryption."
  type        = string
}

variable "app_role_arn" {
  description = "IAM role of the API (ECS task role): the only principal allowed to read/write objects."
  type        = string
}

variable "s3_vpc_endpoint_id" {
  description = "Gateway endpoint the API uses; its reads are exempt from the malware-scan gate."
  type        = string
}

variable "cors_allowed_origins" {
  description = "Browser origins allowed to use presigned URLs directly (empty = no CORS)."
  type        = list(string)
  default     = []
}

variable "noncurrent_version_days" {
  description = "How long deleted/overwritten object versions are kept."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty Malware Protection for S3 and gate downloads on a clean scan."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete non-empty buckets (dev only)."
  type        = bool
  default     = false
}
