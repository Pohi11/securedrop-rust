variable "name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "jwt_secret_version" {
  description = "Increment to rotate the JWT signing key (invalidates all access tokens; refresh tokens survive)."
  type        = number
  default     = 1
}
