terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
# S3 bucket for static website hosting
resource "aws_s3_bucket" "resume_bucket" {
  bucket = "rt-buckwheats-curriculum-vitae"
}

# S3 bucket website configuration
resource "aws_s3_bucket_website_configuration" "resume_website" {
  bucket = aws_s3_bucket.resume_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# S3 bucket public access block (allows public read)
resource "aws_s3_bucket_public_access_block" "resume_bucket_pab" {
  bucket = aws_s3_bucket.resume_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# S3 bucket policy for public read access
resource "aws_s3_bucket_policy" "resume_bucket_policy" {
  bucket = aws_s3_bucket.resume_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.resume_bucket.arn}/*"
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.resume_bucket_pab]
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "resume_distribution" {
  origin {
    domain_name = aws_s3_bucket_website_configuration.resume_website.website_endpoint
    origin_id   = "rt-buckwheats-curriculum-vitae"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  # Both your domains
  aliases = ["ricardot.com", "www.ricardot.com"]

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "rt-buckwheats-curriculum-vitae"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"  # Matches your current setup
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

viewer_certificate {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:503561451261:certificate/1f7f399f-ca8d-4d6e-aaf0-30b73fcf210c"
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  price_class = "PriceClass_All"

  tags = {
    Name = "Resume CloudFront Distribution"
  }
}

# DynamoDB table for visitor counter
resource "aws_dynamodb_table" "visitor_counter" {
  name           = "VisitorCounter" 
  billing_mode   = "PAY_PER_REQUEST" 
  hash_key       = "id"              

  attribute {
    name = "id"                      
    type = "S"                       
  }

  tags = {
    Name        = "Resume Visitor Counter"
    Environment = "Production"
  }
}

# Reference existing IAM role for Lambda function
data "aws_iam_role" "lambda_execution_role" {
  name = "VisitorCounterLambdaRole"
}

# Lambda function
resource "aws_lambda_function" "visitor_counter" {
  filename         = "lambda_function.zip"
  function_name    = "VisitorCounterFunction"
  role            = data.aws_iam_role.lambda_execution_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.11"
  timeout         = 3
  memory_size     = 128

  environment {
    variables = {
      DYNAMODB_TABLE = "VisitorCounter"
    }
  }

  # Ignore code changes during import
  lifecycle {
    ignore_changes = [
      filename,
      source_code_hash,
    ]
  }

  tags = {
    Name = "Resume Visitor Counter Function"
  }
}

# Reference existing API Gateway REST API
data "aws_api_gateway_rest_api" "visitor_counter_api" {
  name = "VisitorCounterAPI"
}

# Lambda permission for API Gateway to invoke the function
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.visitor_counter.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${data.aws_api_gateway_rest_api.visitor_counter_api.execution_arn}/*/*"
}
