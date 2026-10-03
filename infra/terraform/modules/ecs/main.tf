# ECS Fargate service behind an HTTPS Application Load Balancer.
#
#   Internet ──443──► ALB (public subnets, TLS 1.2+/1.3, optional WAF)
#                       │ 8080 (SG-to-SG rule)
#                       ▼
#                  ECS tasks (app subnets, no public IP, read-only rootfs, non-root)
#                       │
#          RDS / Valkey (data subnets)   S3 / KMS / Secrets / Logs (VPC endpoints)

data "aws_caller_identity" "current" {}

locals {
  container_name = "api"
}

# =============================================================================================
# Security groups
# =============================================================================================

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public HTTPS to the load balancer"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS from anywhere"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  #checkov:skip=CKV_AWS_260:Port 80 only serves a 301 redirect to HTTPS (see http_redirect listener).
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  description       = "HTTP (redirected to HTTPS)"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  description                  = "Forward to API tasks"
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = var.app_security_group_id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  description                  = "API traffic from the ALB only (metrics port 9100 is not exposed)"
}

# =============================================================================================
# Load balancer
# =============================================================================================

# Internet-facing on purpose: this is the public API entry point, fronted by WAF, and it only
# forwards to the API tasks' security group.
#trivy:ignore:AWS-0053
resource "aws_lb" "this" {
  #checkov:skip=CKV2_AWS_28:The WAF web ACL is associated in modules/waf (enabled by default via enable_waf).
  name                       = "${var.name}-alb"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true # reject requests with malformed headers (smuggling)
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 60

  access_logs {
    bucket  = var.log_bucket_name
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "api" {
  name                 = "${var.name}-api"
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30 # matches the app's graceful-shutdown drain

  health_check {
    path                = "/readyz" # readiness: dependencies reachable
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  # TLS 1.3 preferred, 1.2 minimum, forward-secret ciphers only.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# =============================================================================================
# IAM
# =============================================================================================

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

# Execution role: used by the ECS *agent* to pull the image, write logs and inject secrets.
# The application code never gets these permissions.
resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "PullImage"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [var.ecr_repository_arn]
  }
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # this action does not support resource-level permissions
  }
  statement {
    sid       = "WriteLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${var.log_group_arn}:*"]
  }
  statement {
    sid       = "ReadSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = values(var.secret_arns)
  }
  statement {
    sid       = "DecryptSecretsAndImage"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# Task role (created by the caller so the bucket policy can reference it): what the
# application itself may do. Scoped to the object prefix the app uses, and to this one key.
data "aws_iam_policy_document" "task" {
  statement {
    sid = "ObjectAccess"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
    ]
    resources = ["${var.bucket_arn}/u/*"]
  }
  statement {
    sid       = "BucketReadiness"
    actions   = ["s3:ListBucket"] # HeadBucket (readiness probe)
    resources = [var.bucket_arn]
  }
  statement {
    # Presigned URLs are executed with the *signer's* permissions: clients downloading
    # SSE-KMS objects need the task role to be allowed to decrypt with the key.
    sid       = "UseDataKeyViaS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  role   = var.task_role_name
  policy = data.aws_iam_policy_document.task.json
}

# =============================================================================================
# ECS
# =============================================================================================

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enhanced"
  }
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = var.task_role_arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = local.container_name
    image     = var.image
    essential = true

    # Hardening that the Dockerfile alone can't enforce:
    readonlyRootFilesystem = true
    user                   = "65532:65532"
    linuxParameters = {
      capabilities       = { drop = ["ALL"] }
      initProcessEnabled = true # reap zombies, forward signals (graceful SIGTERM shutdown)
    }

    portMappings = [
      { containerPort = 8080, protocol = "tcp" },
      { containerPort = 9100, protocol = "tcp" },
    ]

    environment = [for k, v in merge({
      APP_ENV              = "production"
      LOG_FORMAT           = "json"
      RUST_LOG             = "info,securedrop_api=info,tower_http=info,sqlx=warn"
      BIND_ADDR            = "0.0.0.0:8080"
      METRICS_ADDR         = "0.0.0.0:9100"
      AWS_REGION           = var.region
      S3_BUCKET            = var.bucket_name
      S3_SSE_KMS_KEY_ID    = var.kms_key_arn
      TRUST_PROXY_HEADERS  = "true" # behind the ALB, X-Forwarded-For's last hop is trustworthy
      CORS_ALLOWED_ORIGINS = join(",", var.cors_allowed_origins)
      RATE_LIMIT_ENABLED   = "true"
    }, var.extra_environment) : { name = k, value = v }]

    # Injected by the ECS agent from Secrets Manager at start; never in the task definition.
    secrets = [for k, arn in var.secret_arns : { name = k, valueFrom = arn }]

    healthCheck = {
      command     = ["CMD", "/usr/local/bin/securedrop-api", "healthcheck"]
      interval    = 15
      timeout     = 3
      retries     = 3
      startPeriod = 20
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_group_name
        awslogs-region        = var.region
        awslogs-stream-prefix = "api"
      }
    }
  }])
}

resource "aws_ecs_service" "api" {
  name            = "${var.name}-api"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.app_subnet_ids
    security_groups  = [var.app_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = local.container_name
    container_port   = 8080
  }

  # Roll back automatically if new tasks never become healthy.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 30
  enable_execute_command             = false # no shell access into production tasks

  # CI/CD updates the image; Terraform shouldn't fight it on every apply.
  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_appautoscaling_target" "api" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.desired_count
  max_capacity       = var.max_count
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-api-cpu"
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
