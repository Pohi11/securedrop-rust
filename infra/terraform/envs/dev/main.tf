locals {
  name = "securedrop-${var.environment}"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------------------------
# Identity that must exist before the bucket and the service (breaks the dependency cycle
# "bucket policy needs the role ARN" <-> "role policy needs the bucket ARN").
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "api_task" {
  name_prefix        = "${local.name}-task-"
  description        = "Runtime identity of the SecureDrop API (S3 objects, KMS via S3)"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

# Security group for the API tasks. Ingress (from the ALB) is added by the ecs module;
# RDS/cache reference it as their only allowed source.
resource "aws_security_group" "api" {
  #checkov:skip=CKV2_AWS_5:Attached to the ECS service inside modules/ecs (cross-module reference).
  name_prefix = "${local.name}-api-"
  description = "SecureDrop API tasks"
  vpc_id      = module.network.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

# Least-privilege egress: HTTPS (AWS APIs via endpoints/NAT), Postgres and Valkey inside the VPC.
resource "aws_vpc_security_group_egress_rule" "api_https" {
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "AWS APIs (S3, KMS, Secrets Manager, ECR, Logs)"
}

resource "aws_vpc_security_group_egress_rule" "api_postgres" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = module.database.security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "PostgreSQL"
}

resource "aws_vpc_security_group_egress_rule" "api_cache" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = module.cache.security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Valkey"
}

# ---------------------------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------------------------

module "kms" {
  source = "../../modules/kms"
  name   = local.name
  region = var.region
}

module "network" {
  source               = "../../modules/network"
  name                 = local.name
  region               = var.region
  cidr_block           = var.vpc_cidr
  enable_nat_gateway   = var.enable_nat_gateway
  flow_logs_bucket_arn = module.s3.log_bucket_arn
}

module "s3" {
  source                    = "../../modules/s3"
  name                      = local.name
  region                    = var.region
  kms_key_arn               = module.kms.key_arn
  app_role_arn              = aws_iam_role.api_task.arn
  s3_vpc_endpoint_id        = module.network.s3_endpoint_id
  cors_allowed_origins      = var.cors_allowed_origins
  enable_malware_protection = var.enable_malware_protection
  force_destroy             = var.environment != "prod"
}

module "database" {
  source                = "../../modules/database"
  name                  = local.name
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.data_subnet_ids
  app_security_group_id = aws_security_group.api.id
  kms_key_arn           = module.kms.key_arn
  multi_az              = var.db_multi_az
  deletion_protection   = var.deletion_protection
}

module "cache" {
  source                = "../../modules/cache"
  name                  = local.name
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.data_subnet_ids
  app_security_group_id = aws_security_group.api.id
  kms_key_arn           = module.kms.key_arn
}

module "secrets" {
  source      = "../../modules/secrets"
  name        = local.name
  kms_key_arn = module.kms.key_arn
}

module "ecr" {
  source      = "../../modules/ecr"
  name        = local.name
  kms_key_arn = module.kms.key_arn
}

module "observability" {
  source                  = "../../modules/observability"
  name                    = local.name
  kms_key_arn             = module.kms.key_arn
  alarm_email             = var.alarm_email
  alb_arn_suffix          = module.ecs.alb_arn_suffix
  target_group_arn_suffix = module.ecs.target_group_arn_suffix
  cluster_name            = module.ecs.cluster_name
  service_name            = module.ecs.service_name
  db_instance_id          = module.database.instance_id
}

module "ecs" {
  source                = "../../modules/ecs"
  name                  = local.name
  region                = var.region
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  app_subnet_ids        = module.network.app_subnet_ids
  app_security_group_id = aws_security_group.api.id
  certificate_arn       = var.certificate_arn
  image                 = "${module.ecr.repository_url}:${var.image_tag}"
  ecr_repository_arn    = module.ecr.repository_arn
  task_role_arn         = aws_iam_role.api_task.arn
  task_role_name        = aws_iam_role.api_task.name
  bucket_name           = module.s3.bucket_name
  bucket_arn            = module.s3.bucket_arn
  kms_key_arn           = module.kms.key_arn
  log_group_name        = module.observability.log_group_name
  log_group_arn         = module.observability.log_group_arn
  log_bucket_name       = module.s3.log_bucket_name
  cors_allowed_origins  = var.cors_allowed_origins
  desired_count         = var.desired_count
  deletion_protection   = var.deletion_protection

  secret_arns = {
    DATABASE_URL = module.database.database_url_secret_arn
    REDIS_URL    = module.cache.redis_url_secret_arn
    JWT_SECRET   = module.secrets.jwt_secret_arn
  }
}

module "waf" {
  count       = var.enable_waf ? 1 : 0
  source      = "../../modules/waf"
  name        = local.name
  alb_arn     = module.ecs.alb_arn
  kms_key_arn = module.kms.key_arn
}

module "github_oidc" {
  count                = var.github_repository == null ? 0 : 1
  source               = "../../modules/github_oidc"
  name                 = local.name
  region               = var.region
  github_repository    = var.github_repository
  create_oidc_provider = var.create_github_oidc_provider
  ecr_repository_arn   = module.ecr.repository_arn
  kms_key_arn          = module.kms.key_arn
  cluster_name         = module.ecs.cluster_name
  service_name         = module.ecs.service_name
  pass_role_arns       = [aws_iam_role.api_task.arn, module.ecs.execution_role_arn]
}
