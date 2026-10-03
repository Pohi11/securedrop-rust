variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Data-tier subnets (no internet route)."
  type        = list(string)
}

variable "app_security_group_id" {
  description = "Security group of the API tasks (the only allowed client)."
  type        = string
}

variable "kms_key_arn" {
  type = string
}

variable "engine_version" {
  type    = string
  default = "17"
}

variable "instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "multi_az" {
  type    = bool
  default = false
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "password_version" {
  description = "Increment to rotate the master password (write-only arguments only change when their version does)."
  type        = number
  default     = 1
}
