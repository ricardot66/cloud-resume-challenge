output "website_url" {
  description = "CloudFront distribution URL for the resume website"
  value       = "https://${aws_cloudfront_distribution.resume_distribution.domain_name}"
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket hosting the website"
  value       = aws_s3_bucket.resume_bucket.bucket
}

output "s3_website_endpoint" {
  description = "S3 bucket website endpoint"
  value       = aws_s3_bucket_website_configuration.resume_website.website_endpoint
}

output "lambda_function_name" {
  description = "Name of the visitor counter Lambda function"
  value       = aws_lambda_function.visitor_counter.function_name
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table for visitor counter"
  value       = aws_dynamodb_table.visitor_counter.name
}

# Note: API Gateway URL would need the actual deployment resource
# Since you're using data source, we'll add this when you have the full API setup
