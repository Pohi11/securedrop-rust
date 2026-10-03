# PostgreSQL on RDS, in data subnets with no internet route.
#
# Secrets handling: the master password is generated as an *ephemeral* value and passed to
# RDS through a *write-only* argument (`password_wo`), so it never appears in Terraform
# state or plan files. The same ephemeral value builds the application's DATABASE_URL,
# written to Secrets Manager through another write-only argument (`secret_string_wo`).
# Rotate by bumping `password_version`.

ephemeral "random_password" "master" {
  length           = 40
  special          = true
  override_special = "-_~" # URL-safe: the password is embedded in DATABASE_URL
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-db"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL from the API tasks only"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "API tasks"
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg17-"
  family      = "postgres17"

  # Reject any non-TLS connection at the server.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "500" # log queries slower than 500 ms
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name}-db"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name             = "securedrop"
  username            = "securedrop"
  password_wo         = ephemeral.random_password.master.result
  password_wo_version = var.password_version

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false
  multi_az               = var.multi_az

  backup_retention_period         = 7
  copy_tags_to_snapshot           = true
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = !var.deletion_protection
  final_snapshot_identifier       = var.deletion_protection ? "${var.name}-db-final" : null
  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # OS-level metrics every 60 s (CPU steal, memory, disk queue) beyond what CloudWatch shows.
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.monitoring.arn

  # Lets humans connect with short-lived IAM tokens instead of the master password.
  iam_database_authentication_enabled = true

  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.kms_key_arn
}

resource "aws_secretsmanager_secret" "database_url" {
  #checkov:skip=CKV2_AWS_57:Rotated by bumping password_version (write-only args); a rotation Lambda is the next step.
  name_prefix = "${var.name}/database-url-"
  description = "DATABASE_URL for the SecureDrop API"
  kms_key_id  = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id                = aws_secretsmanager_secret.database_url.id
  secret_string_wo         = "postgres://securedrop:${ephemeral.random_password.master.result}@${aws_db_instance.this.endpoint}/securedrop?sslmode=require"
  secret_string_wo_version = var.password_version
}

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  name_prefix        = "${var.name}-rds-mon-"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
