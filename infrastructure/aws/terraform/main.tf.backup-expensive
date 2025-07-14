# KMS Key for encryption at rest
resource "aws_kms_key" "main" {
  description             = "${local.name_prefix} encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name_prefix}-encryption-key"
  target_key_id = aws_kms_key.main.key_id
}

# VPC for Lambda security
resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-vpc"
  })
}

resource "aws_subnet" "lambda_private" {
  count             = 2
  vpc_id            = aws_vpc.lambda_vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-private-${count.index + 1}"
  })
}

resource "aws_subnet" "lambda_public" {
  count                   = 2
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.0.${count.index + 10}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-public-${count.index + 1}"
  })
}

resource "aws_internet_gateway" "lambda_igw" {
  vpc_id = aws_vpc.lambda_vpc.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-igw"
  })
}

resource "aws_route_table" "lambda_public" {
  vpc_id = aws_vpc.lambda_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lambda_igw.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-public-rt"
  })
}

resource "aws_route_table_association" "lambda_public" {
  count          = 2
  subnet_id      = aws_subnet.lambda_public[count.index].id
  route_table_id = aws_route_table.lambda_public.id
}

resource "aws_nat_gateway" "lambda_nat" {
  count         = 2
  allocation_id = aws_eip.lambda_nat[count.index].id
  subnet_id     = aws_subnet.lambda_public[count.index].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-nat-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.lambda_igw]
}

resource "aws_eip" "lambda_nat" {
  count  = 2
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-nat-eip-${count.index + 1}"
  })
}

resource "aws_route_table" "lambda_private" {
  count  = 2
  vpc_id = aws_vpc.lambda_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.lambda_nat[count.index].id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-private-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "lambda_private" {
  count          = 2
  subnet_id      = aws_subnet.lambda_private[count.index].id
  route_table_id = aws_route_table.lambda_private[count.index].id
}

# Security Group for Lambda
resource "aws_security_group" "lambda_sg" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.lambda_vpc.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound for AWS services"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-sg"
  })
}

# VPC Endpoint for DynamoDB
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.lambda_vpc.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.lambda_private[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-dynamodb-endpoint"
  })
}

data "aws_availability_zones" "available" {
  state = "available"
}

# S3 Bucket for Website with Maximum Security
resource "aws_s3_bucket" "website" {
  bucket = "${local.name_prefix}-website-${random_string.bucket_suffix.result}"
  tags   = local.common_tags
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket Security Configuration (All 4 public access blocks)
resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "website" {
  bucket = aws_s3_bucket.website.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  rule {
    id     = "abort_incomplete_multipart_uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "delete_old_versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_logging" "website" {
  bucket = aws_s3_bucket.website.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "website-access-logs/"
}

# S3 Bucket for Access Logs
resource "aws_s3_bucket" "access_logs" {
  bucket = "${local.name_prefix}-access-logs-${random_string.bucket_suffix.result}"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "delete_old_logs"
    status = "Enabled"

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "website" {
  name                              = "${local.name_prefix}-oac"
  description                       = "OAC for ${local.name_prefix} website"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Enhanced WAF with Log4j protection
resource "aws_wafv2_web_acl" "website" {
  name  = "${local.name_prefix}-waf"
  scope = "CLOUDFRONT"
  tags  = local.common_tags

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }

    action {
      block {}
    }
  }

  # AWS Managed Rules for Common attacks
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

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
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Log4j protection rule
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "WebACL"
    sampled_requests_enabled   = true
  }
}

# CloudFront Distribution with Maximum Security
resource "aws_cloudfront_distribution" "website" {
  count = var.enable_cdn ? 1 : 0

  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.website.id
    origin_id                = "S3-${aws_s3_bucket.website.bucket}"
  }

  # Failover origin configuration
  origin {
    domain_name = aws_s3_bucket.failover_website.bucket_regional_domain_name
    origin_id   = "S3-failover-${aws_s3_bucket.failover_website.bucket}"

    origin_access_control_id = aws_cloudfront_origin_access_control.website.id
  }

  origin_group {
    origin_id = "S3-origin-group"

    failover_criteria {
      status_codes = [403, 404, 500, 502, 503, 504]
    }

    member {
      origin_id = "S3-${aws_s3_bucket.website.bucket}"
    }

    member {
      origin_id = "S3-failover-${aws_s3_bucket.failover_website.bucket}"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${local.name_prefix} resume website distribution"
  default_root_object = "index.html"

  # Geographic restrictions for security
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "MX", "GB", "DE", "FR", "JP", "AU"]
    }
  }

  # Access logging
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.cloudfront_logs.bucket_domain_name
    prefix          = "cloudfront-logs/"
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-origin-group"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # Force HTTPS
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # WAF Association
  web_acl_id = aws_wafv2_web_acl.website.arn

  viewer_certificate {
    cloudfront_default_certificate = var.domain_name == "" ? true : false
    acm_certificate_arn            = var.domain_name != "" ? aws_acm_certificate.website[0].arn : null
    ssl_support_method             = var.domain_name != "" ? "sni-only" : null
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = local.common_tags
}

# Failover S3 Bucket
resource "aws_s3_bucket" "failover_website" {
  bucket = "${local.name_prefix}-failover-${random_string.bucket_suffix.result}"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "failover_website" {
  bucket = aws_s3_bucket.failover_website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "failover_website" {
  bucket = aws_s3_bucket.failover_website.id

  rule {
    id     = "abort_incomplete_multipart_uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# CloudFront Logs Bucket
resource "aws_s3_bucket" "cloudfront_logs" {
  bucket = "${local.name_prefix}-cf-logs-${random_string.bucket_suffix.result}"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id

  rule {
    id     = "delete_old_logs"
    status = "Enabled"

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# S3 Bucket Policy for CloudFront OAC
resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.website.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = var.enable_cdn ? aws_cloudfront_distribution.website[0].arn : ""
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.website]
}

# DynamoDB Table with KMS Encryption
resource "aws_dynamodb_table" "visitor_count" {
  name         = "${local.name_prefix}-visitor-count"
  billing_mode = var.dynamodb_billing_mode
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Enable KMS encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = local.common_tags
}

# SQS Dead Letter Queue for Lambda
resource "aws_sqs_queue" "lambda_dlq" {
  name = "${local.name_prefix}-lambda-dlq"

  kms_master_key_id                 = aws_kms_key.main.arn
  kms_data_key_reuse_period_seconds = 300

  tags = local.common_tags
}

# Lambda Execution Role with enhanced permissions
resource "aws_iam_role" "lambda_execution" {
  name = "${local.name_prefix}-lambda-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.name_prefix}-lambda-dynamodb"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.visitor_count.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_execution.name
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
  role       = aws_iam_role.lambda_execution.name
}

resource "aws_iam_role_policy" "lambda_xray" {
  name = "${local.name_prefix}-lambda-xray"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda Function with Maximum Security
resource "aws_lambda_function" "visitor_counter" {
  filename      = "lambda.zip"
  function_name = "${local.name_prefix}-visitor-counter"
  role          = aws_iam_role.lambda_execution.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  # VPC Configuration
  vpc_config {
    subnet_ids         = aws_subnet.lambda_private[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  # Dead Letter Queue
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # X-Ray Tracing
  tracing_config {
    mode = "Active"
  }

  # Environment variables with KMS encryption
  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.visitor_count.name
      ENVIRONMENT    = var.environment
    }
  }

  kms_key_arn = aws_kms_key.main.arn

  # Enable function-level concurrency control
  reserved_concurrent_executions = 10

  tags = local.common_tags

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy_attachment.lambda_vpc,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# CloudWatch Log Groups with KMS encryption
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.name_prefix}-visitor-counter"
  retention_in_days = local.config.retention_in_days
  kms_key_id        = aws_kms_key.main.arn
  tags              = local.common_tags
}

# API Gateway with enhanced security
resource "aws_api_gateway_rest_api" "visitor_counter" {
  name        = "${local.name_prefix}-visitor-api"
  description = "Visitor Counter API for ${local.name_prefix}"

  endpoint_configuration {
    types = ["EDGE"]
  }

  tags = local.common_tags
}

resource "aws_api_gateway_resource" "count" {
  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id
  parent_id   = aws_api_gateway_rest_api.visitor_counter.root_resource_id
  path_part   = "count"
}

resource "aws_api_gateway_method" "count_get" {
  rest_api_id   = aws_api_gateway_rest_api.visitor_counter.id
  resource_id   = aws_api_gateway_resource.count.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "count_options" {
  rest_api_id   = aws_api_gateway_rest_api.visitor_counter.id
  resource_id   = aws_api_gateway_resource.count.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "count_get" {
  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id
  resource_id = aws_api_gateway_resource.count.id
  http_method = aws_api_gateway_method.count_get.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.visitor_counter.invoke_arn
}

resource "aws_api_gateway_integration" "count_options" {
  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id
  resource_id = aws_api_gateway_resource.count.id
  http_method = aws_api_gateway_method.count_options.http_method

  type = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "count_options" {
  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id
  resource_id = aws_api_gateway_resource.count.id
  http_method = aws_api_gateway_method.count_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "count_options" {
  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id
  resource_id = aws_api_gateway_resource.count.id
  http_method = aws_api_gateway_method.count_options.http_method
  status_code = aws_api_gateway_method_response.count_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

resource "aws_api_gateway_deployment" "visitor_counter" {
  depends_on = [
    aws_api_gateway_integration.count_get,
    aws_api_gateway_integration.count_options
  ]

  rest_api_id = aws_api_gateway_rest_api.visitor_counter.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.count.id,
      aws_api_gateway_method.count_get.id,
      aws_api_gateway_method.count_options.id,
      aws_api_gateway_integration.count_get.id,
      aws_api_gateway_integration.count_options.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "visitor_counter" {
  deployment_id = aws_api_gateway_deployment.visitor_counter.id
  rest_api_id   = aws_api_gateway_rest_api.visitor_counter.id
  stage_name    = var.environment

  # Enable access logging
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-visitor-api"
  retention_in_days = local.config.retention_in_days
  kms_key_id        = aws_kms_key.main.arn
  tags              = local.common_tags
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.visitor_counter.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.visitor_counter.execution_arn}/*/*"
}

# SSL Certificate (if domain provided)
resource "aws_acm_certificate" "website" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}
