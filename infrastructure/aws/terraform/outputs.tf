output "lambda_function_name" {
  value = aws_lambda_function.visitor_counter.function_name
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.visitor_count.name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.website_distribution.id
}

output "cloudfront_distribution_domain_name" {
  value = aws_cloudfront_distribution.website_distribution.domain_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.website.bucket
}

