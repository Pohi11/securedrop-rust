variable "name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "keep_images" {
  type    = number
  default = 30
}
