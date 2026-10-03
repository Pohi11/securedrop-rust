variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "app_security_group_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "engine_version" {
  type    = string
  default = "8.0"
}

variable "node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "num_cache_clusters" {
  description = "1 = single node (dev); 2+ = primary with replicas and automatic failover."
  type        = number
  default     = 1
}

variable "auth_token_version" {
  description = "Increment to rotate the AUTH token."
  type        = number
  default     = 1
}
