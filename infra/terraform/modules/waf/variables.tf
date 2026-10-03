variable "name" {
  type = string
}

variable "alb_arn" {
  type = string
}

variable "requests_per_5_minutes_per_ip" {
  type    = number
  default = 2000
}

variable "auth_requests_per_5_minutes_per_ip" {
  type    = number
  default = 100
}

variable "kms_key_arn" {
  description = "CMK for the WAF log group."
  type        = string
}
