output "lambda_function_name" {
  value = aws_lambda_function.lambda_function.function_name
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.cloud_resume_dev_visitor_count.name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.cloud_resume_dev_website_3ikujxky.id
}

output "cloudfront_distribution_domain_name" {
  value = aws_cloudfront_distribution.cloud_resume_dev_website_3ikujxky.domain_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.cloud_resume_bucket.bucket
}

