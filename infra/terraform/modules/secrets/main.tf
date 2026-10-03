# Application secrets that aren't owned by a specific data store.
# The JWT signing key is generated ephemerally and written with a write-only argument, so it
# exists only in Secrets Manager (encrypted with our CMK), never in Terraform state.

ephemeral "random_password" "jwt" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "jwt" {
  #checkov:skip=CKV2_AWS_57:Rotated deliberately via jwt_secret_version (invalidates all access tokens); not on a timer.
  name_prefix = "${var.name}/jwt-secret-"
  description = "HS256 signing key for SecureDrop access tokens"
  kms_key_id  = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id                = aws_secretsmanager_secret.jwt.id
  secret_string_wo         = ephemeral.random_password.jwt.result
  secret_string_wo_version = var.jwt_secret_version
}
