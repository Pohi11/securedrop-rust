# The file bucket (and a separate access-log bucket).
#
# Defence in depth for the bucket:
#   1. Block Public Access (all four settings) + ACLs disabled (BucketOwnerEnforced)
#   2. Default encryption SSE-KMS with our CMK + S3 Bucket Keys (fewer KMS calls, lower cost)
#   3. Bucket policy: TLS-only, TLS >= 1.2, no other encryption keys, no SSE-S3 downgrade
#   4. Versioning: deleted/overwritten objects recoverable for `noncurrent_version_days`
#   5. Lifecycle: abort incomplete multipart uploads (cost control backstop for the app worker)
#   6. Optional GuardDuty Malware Protection: new objects are scanned and tagged; clients
#      cannot download an object until it is tagged NO_THREATS_FOUND
#   7. Server access logs to a separate, locked-down bucket

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name     = "${var.name}-files-${random_id.suffix.hex}"
  log_bucket_name = "${var.name}-logs-${random_id.suffix.hex}"
}

# =============================================================================================
# Log bucket (S3 server access logs, ALB access logs, VPC flow logs)
# =============================================================================================

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_144:Log bucket; cross-region replication not required (logs are also in CloudWatch).
  #checkov:skip=CKV_AWS_145:ALB access logs only support SSE-S3 on the destination bucket.
  #checkov:skip=CKV_AWS_18:This IS the access-log bucket; logging it to itself would loop.
  #checkov:skip=CKV2_AWS_62:No consumers for log-object events.
  bucket        = local.log_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# ALB access logs only support SSE-S3 on the destination bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "AllowLogDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
    principals {
      type = "Service"
      identifiers = [
        "logging.s3.amazonaws.com",                       # S3 server access logs
        "logdelivery.elasticloadbalancing.amazonaws.com", # ALB access logs
        "delivery.logs.amazonaws.com",                    # VPC flow logs
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "AllowFlowLogsAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# =============================================================================================
# File bucket
# =============================================================================================

resource "aws_s3_bucket" "files" {
  #checkov:skip=CKV_AWS_144:Single-region by design; versioning + the 30-day noncurrent window cover recovery. Add CRR for DR requirements.
  bucket        = local.bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "files" {
  bucket                  = aws_s3_bucket.files.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "files" {
  bucket = aws_s3_bucket.files.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "files" {
  bucket = aws_s3_bucket.files.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    # Bucket Keys: S3 derives per-object keys from a bucket-level key, cutting KMS
    # requests (and cost) by orders of magnitude for many small objects.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "files" {
  bucket = aws_s3_bucket.files.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "files" {
  bucket        = aws_s3_bucket.files.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/"
}

# Object events to EventBridge (GuardDuty scan results, future automation such as thumbnails).
resource "aws_s3_bucket_notification" "files" {
  bucket      = aws_s3_bucket.files.id
  eventbridge = true
}

resource "aws_s3_bucket_lifecycle_configuration" "files" {
  bucket = aws_s3_bucket.files.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    # Backstop for the application's cleanup worker: parts of abandoned uploads are billed
    # but invisible, so S3 itself discards them after a day.
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}
    # Deleted files stay recoverable for a while (accidental or malicious deletion), then go.
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_days
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# Needed only if browsers upload/download directly (presigned URLs from a web front-end).
resource "aws_s3_bucket_cors_configuration" "files" {
  count  = length(var.cors_allowed_origins) > 0 ? 1 : 0
  bucket = aws_s3_bucket.files.id

  cors_rule {
    allowed_origins = var.cors_allowed_origins
    allowed_methods = ["GET", "PUT"]
    allowed_headers = [
      "content-type",
      "content-length",
      "x-amz-checksum-sha256",
      "x-amz-server-side-encryption",
      "x-amz-server-side-encryption-aws-kms-key-id",
    ]
    # Browsers must be able to read the part ETag to complete multipart uploads.
    expose_headers  = ["ETag"]
    max_age_seconds = 600
  }
}

data "aws_iam_policy_document" "files" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.files.arn, "${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOutdatedTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.files.arn, "${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  # Writers may not downgrade to SSE-S3...
  statement {
    sid       = "DenySseS3Downgrade"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }

  # ...or encrypt with a key we don't control (which could be deleted to hold data hostage).
  statement {
    sid       = "DenyForeignKmsKeys"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }
  }

  # Only the application may touch the bucket's object space at all.
  statement {
    sid       = "DenyOtherPrincipals"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.files.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = compact([var.app_role_arn, local.malware_role_arn])
    }
  }

  # With malware protection: clients can't download an object until GuardDuty has tagged it
  # clean. The API's own reads (512-byte sniff on completion) come through the S3 gateway
  # endpoint and are exempt; presigned downloads come from the internet and are not.
  dynamic "statement" {
    for_each = var.enable_malware_protection ? [1] : []
    content {
      sid       = "DenyUnscannedDownloads"
      effect    = "Deny"
      actions   = ["s3:GetObject"]
      resources = ["${aws_s3_bucket.files.arn}/*"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      condition {
        test     = "StringNotEquals"
        variable = "s3:ExistingObjectTag/GuardDutyMalwareScanStatus"
        values   = ["NO_THREATS_FOUND"]
      }
      condition {
        test     = "StringNotEqualsIfExists"
        variable = "aws:SourceVpce"
        values   = [var.s3_vpc_endpoint_id]
      }
      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = compact([local.malware_role_arn])
      }
    }
  }
}

resource "aws_s3_bucket_policy" "files" {
  bucket     = aws_s3_bucket.files.id
  policy     = data.aws_iam_policy_document.files.json
  depends_on = [aws_s3_bucket_public_access_block.files]
}

# =============================================================================================
# GuardDuty Malware Protection for S3 (optional)
# =============================================================================================

locals {
  malware_role_arn = var.enable_malware_protection ? aws_iam_role.malware[0].arn : ""
}

data "aws_iam_policy_document" "malware_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["malware-protection-plan.guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "malware" {
  count              = var.enable_malware_protection ? 1 : 0
  name_prefix        = "${var.name}-gd-malware-"
  assume_role_policy = data.aws_iam_policy_document.malware_assume.json
}

data "aws_iam_policy_document" "malware" {
  statement {
    sid = "EventBridgeManagedRule"
    actions = [
      "events:PutRule",
      "events:DeleteRule",
      "events:PutTargets",
      "events:RemoveTargets",
      "events:DescribeRule",
      "events:ListTargetsByRule",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:events:${var.region}:${data.aws_caller_identity.current.account_id}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"]
  }
  statement {
    sid = "ScanAndTagObjects"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.files.arn}/*"]
  }
  statement {
    sid = "BucketConfiguration"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketNotification",
      "s3:PutBucketNotification",
      "s3:GetBucketLocation",
    ]
    resources = [aws_s3_bucket.files.arn]
  }
  statement {
    sid       = "DecryptObjects"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.*.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "malware" {
  count  = var.enable_malware_protection ? 1 : 0
  role   = aws_iam_role.malware[0].id
  policy = data.aws_iam_policy_document.malware.json
}

resource "aws_guardduty_malware_protection_plan" "files" {
  count = var.enable_malware_protection ? 1 : 0
  role  = aws_iam_role.malware[0].arn

  protected_resource {
    s3_bucket {
      bucket_name     = aws_s3_bucket.files.id
      object_prefixes = ["u/"]
    }
  }

  actions {
    tagging {
      status = "ENABLED"
    }
  }

  depends_on = [aws_iam_role_policy.malware]
}
