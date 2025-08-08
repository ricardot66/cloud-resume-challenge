provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_sqs_queue" "lambda_dlq" {
  name = "lambda-dlq"
  kms_master_key_id = aws_kms_key.dynamodb_kms.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_kms_key" "dynamodb_kms" {
  description             = "CMK for DynamoDB encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "Enable IAM User Permissions",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "kms:*",
        Resource = "*"
      }
    ]
  })
}

resource "aws_dynamodb_table" "visitor_count" {
  name         = "cloud-resume-dev-visitor-count"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_kms.arn
  }
}

resource "aws_lambda_function" "visitor_counter" {
  function_name = "visitor-counter"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_exec.arn
  filename      = "lambda_function.zip"

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.visitor_count.name
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  reserved_concurrent_executions = 10

  kms_key_arn = aws_kms_key.dynamodb_kms.arn

resource "aws_iam_role" "lambda_exec" {
  name = "lambda_exec_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "security-headers-policy"
  security_headers_config {
    content_security_policy {
      override = true
      content_security_policy = "default-src 'self';"
    }
    strict_transport_security {
      override = true
      access_control_max_age_sec = 31536000
      include_subdomains = true
      preload = true
    }
    xss_protection {
      override = true
      protection = true
      mode_block = true
    }
    content_type_options {
      override = true
    }
    referrer_policy {
      override = true
      referrer_policy = "strict-origin-when-cross-origin"
    }
  }
}

resource "aws_cloudfront_distribution" "website_distribution" {
  origin {
    domain_name = aws_s3_bucket.website.bucket_regional_domain_name
    origin_id   = "s3-origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Cloud Resume website"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "s3-origin"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA"]
    }
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
  }

  web_acl_id = aws_wafv2_web_acl.resume_acl.arn

  origin_group {
    origin_id = "origin-group-1"

    failover_criteria {
      status_codes = [403, 404, 500, 502, 503, 504]
    }

    member {
      origin_id = "s3-origin"
    }

    member {
      origin_id = aws_s3_bucket.backup.id
    }
  }
}

resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "OAI for S3 Cloud Resume"
}

resource "aws_s3_bucket" "website" {
  bucket = "cloud-resume-dev-website-3ikujxky"

  acl           = "private"
  force_destroy = true

  versioning {
    enabled = true
  }

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}

resource "aws_s3_bucket" "backup" {
  bucket = "cloud-resume-dev-website-backup-3ikujxky"

  acl           = "private"
  force_destroy = true

  versioning {
    enabled = true
  }

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}

resource "aws_s3_bucket_policy" "website_policy" {
  bucket = aws_s3_bucket.website.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.oai.iam_arn
        },
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.website.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket" "logs" {
  bucket        = "cloud-resume-dev-logs"
  force_destroy = true
  acl           = "log-delivery-write"

  versioning {
    enabled = true
  }
}

resource "aws_wafv2_web_acl" "resume_acl" {
  name        = "resume-acl"
  description = "WAF ACL for Cloud Resume Challenge"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "aws-managed-common-rules"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
        rule_action_override {
          action_to_use {
            block {}
          }
          name = "Log4jCVE-2021-44228"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "aws-managed-bad-inputs"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "resume-acl"
    sampled_requests_enabled   = false
  }
}

