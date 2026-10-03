# Redis-compatible cache (ElastiCache for Valkey) for rate limiting and the session denylist.
# TLS in transit, encryption at rest with our CMK, AUTH token required, data subnets only.

ephemeral "random_password" "auth" {
  length  = 64
  special = false # ElastiCache AUTH tokens allow only printable chars minus a few; alnum is safest
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-cache"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "cache" {
  name_prefix = "${var.name}-cache-"
  description = "Valkey/Redis from the API tasks only"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  security_group_id            = aws_security_group.cache.id
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "API tasks"
}

resource "aws_elasticache_replication_group" "this" {
  #checkov:skip=CKV_AWS_31:Auth token IS set via the write-only auth_token_wo argument, which Checkov does not recognise yet.
  #checkov:skip=CKV2_AWS_50:Single node in dev by default; set num_cache_clusters >= 2 for automatic Multi-AZ failover.
  replication_group_id = "${var.name}-cache"
  description          = "SecureDrop rate limits and session revocations"
  engine               = "valkey"
  engine_version       = var.engine_version
  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_clusters
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.cache.id]

  automatic_failover_enabled = var.num_cache_clusters > 1
  multi_az_enabled           = var.num_cache_clusters > 1

  at_rest_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"
  auth_token_wo              = ephemeral.random_password.auth.result
  auth_token_wo_version      = var.auth_token_version
  auth_token_update_strategy = "ROTATE"
}

resource "aws_secretsmanager_secret" "redis_url" {
  #checkov:skip=CKV2_AWS_57:Rotated by bumping auth_token_version (ROTATE strategy keeps old token valid during rollout).
  name_prefix = "${var.name}/redis-url-"
  description = "REDIS_URL for the SecureDrop API"
  kms_key_id  = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id = aws_secretsmanager_secret.redis_url.id
  # rediss:// = TLS
  secret_string_wo         = "rediss://:${ephemeral.random_password.auth.result}@${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0"
  secret_string_wo_version = var.auth_token_version
}
