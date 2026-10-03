output "endpoint" {
  value = aws_db_instance.this.endpoint
}

output "security_group_id" {
  value = aws_security_group.db.id
}

output "database_url_secret_arn" {
  value = aws_secretsmanager_secret.database_url.arn
}

output "instance_id" {
  value = aws_db_instance.this.identifier
}
