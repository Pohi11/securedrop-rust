# Logs and alarms.
#
# The log group is created here (not by the ECS agent) so retention and KMS encryption are
# explicit. Alarms publish to an encrypted SNS topic; subscribe email/PagerDuty/Slack to it.

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.name}-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-alarms"
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Metric filter: count audit events where a refresh token was reused (possible token theft).
resource "aws_cloudwatch_log_metric_filter" "refresh_reuse" {
  name           = "${var.name}-refresh-token-reuse"
  log_group_name = aws_cloudwatch_log_group.api.name
  pattern        = "{ $.action = \"auth.refresh_token_reuse\" }"

  metric_transformation {
    name          = "RefreshTokenReuse"
    namespace     = "SecureDrop"
    value         = "1"
    default_value = "0"
  }
}

locals {
  alarms = {
    alb-5xx = {
      description = "API returning 5xx errors"
      namespace   = "AWS/ApplicationELB"
      metric      = "HTTPCode_Target_5XX_Count"
      statistic   = "Sum"
      threshold   = 10
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
    }
    alb-latency-p99 = {
      description        = "p99 latency above 2 seconds"
      namespace          = "AWS/ApplicationELB"
      metric             = "TargetResponseTime"
      extended_statistic = "p99"
      threshold          = 2
      dimensions         = { LoadBalancer = var.alb_arn_suffix }
    }
    unhealthy-targets = {
      description = "ALB has unhealthy API tasks (readiness failing)"
      namespace   = "AWS/ApplicationELB"
      metric      = "UnHealthyHostCount"
      statistic   = "Maximum"
      threshold   = 0
      dimensions  = { LoadBalancer = var.alb_arn_suffix, TargetGroup = var.target_group_arn_suffix }
    }
    ecs-cpu = {
      description = "API CPU above 85%"
      namespace   = "AWS/ECS"
      metric      = "CPUUtilization"
      statistic   = "Average"
      threshold   = 85
      dimensions  = { ClusterName = var.cluster_name, ServiceName = var.service_name }
    }
    rds-cpu = {
      description = "Database CPU above 80%"
      namespace   = "AWS/RDS"
      metric      = "CPUUtilization"
      statistic   = "Average"
      threshold   = 80
      dimensions  = { DBInstanceIdentifier = var.db_instance_id }
    }
    refresh-token-reuse = {
      description = "Refresh-token reuse detected (possible session theft)"
      namespace   = "SecureDrop"
      metric      = "RefreshTokenReuse"
      statistic   = "Sum"
      threshold   = 0
      dimensions  = {}
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = local.alarms

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = lookup(each.value, "statistic", null)
  extended_statistic  = lookup(each.value, "extended_statistic", null)
  dimensions          = each.value.dimensions
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}
