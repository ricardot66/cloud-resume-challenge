output "website_url" {
  description = "URL of the resume website"
  value       = "https://${aws_cloudfront_distribution.resume_distribution.domain_name}"
}

output "api_url" {
  description = "URL of the API Gateway"
  value       = aws_api_gateway_deployment.resume_api.invoke_url
}
