# AWS WAF in front of the ALB: the outer, volumetric layer of defence. The application's own
# Redis rate limiter (per user, per route group) is the inner, semantic layer.

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name}-api"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Per-IP flood protection across all paths (5-minute window).
  rule {
    name     = "rate-limit-per-ip"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.requests_per_5_minutes_per_ip
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Tighter limit for credential endpoints (credential stuffing).
  rule {
    name     = "rate-limit-auth"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.auth_requests_per_5_minutes_per_ip
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/v1/auth/"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit-auth"
      sampled_requests_enabled   = true
    }
  }

  # Known-bad IPs (botnets, scanners) from AWS threat intelligence.
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # OWASP-style generic protections (oversized bodies, bad user agents, LFI/RFI patterns...).
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 11
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Exploit payloads such as Log4Shell (CVE-2021-44228) JNDI lookups.
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 12
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# WAF logs (blocked/allowed requests) for incident response. The log group name must start
# with "aws-waf-logs-". Credentials are redacted before they are written.
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}
