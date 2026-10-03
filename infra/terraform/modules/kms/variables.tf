variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "deletion_window_in_days" {
  description = "Waiting period before the key is deleted (7-30). Deleting the key destroys all data encrypted with it."
  type        = number
  default     = 30
}
