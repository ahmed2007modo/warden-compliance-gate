# Synthetic Terraform for the Warden benchmark (no real resources).
resource "aws_cloudtrail" "audit_trail" {
  name           = "audit-trail"
  s3_bucket_name = "audit-artifacts-prod"
  enabled        = false
}

resource "aws_cloudwatch_log_group" "audit_events" {
  name              = "/audit/app-events"
  retention_in_days = 365
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "audit-artifacts-prod"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_artifacts" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_artifacts" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role_policy" "app_runtime" {
  name = "app_runtime"
  role = "app_runtime"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = "arn:aws:s3:::audit-artifacts-prod/*"
      }
    ]
  })
}

resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_errors" {
  alarm_name          = "s3-errors"
  metric_name         = "5xxErrors"
  namespace           = "AWS/S3"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 100
  period              = 60
  evaluation_periods  = 5
}
