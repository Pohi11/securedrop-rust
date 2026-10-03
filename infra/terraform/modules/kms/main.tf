# Customer-managed KMS key for application data: S3 objects, RDS, ElastiCache, Secrets
# Manager, CloudWatch Logs and SNS.
#
# Why a CMK instead of AWS-managed keys? We control the key policy (who can decrypt), can
# audit every use in CloudTrail, can disable the key to crypto-shred all data at once, and
# rotation is explicit.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_root = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:In a key policy, Resource "*" means "this key"; admin is delegated to IAM in this account.
  #checkov:skip=CKV_AWS_111:Same as above: key policies are scoped to their own key.
  #checkov:skip=CKV_AWS_356:Same as above.
  # Key administration stays with the account (IAM policies decide which principals).
  # Without this statement a key can become unmanageable.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }

  # CloudWatch Logs encrypts log groups with this key, but only for this account's log groups.
  statement {
    sid = "CloudWatchLogs"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  # SNS (alarm topic) and CloudWatch alarms publishing to an encrypted topic.
  statement {
    sid       = "AlarmNotifications"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "sns.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name} application data key"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.this.key_id
}
