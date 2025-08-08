variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloud-resume"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the website (e.g., ricardot.com)"
  type        = string
  default     = ""
}

variable "enable_cdn" {
  description = "Enable CloudFront CDN"
  type        = bool
  default     = true
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 128

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "dynamodb_billing_mode" {
  description = "DynamoDB billing mode"
  type        = string
  default     = "PAY_PER_REQUEST"

  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.dynamodb_billing_mode)
    error_message = "DynamoDB billing mode must be PAY_PER_REQUEST or PROVISIONED."
  }
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alarms"
  type        = bool
  default     = true
}

variable "cost_allocation_tags" {
  description = "Additional tags for cost allocation"
  type        = map(string)
  default     = {}
}

# Environment-specific configurations (demonstrates program management planning)

locals {
  environment_config = {
    dev = {
      lambda_memory     = 128
      lambda_timeout    = 30
      dynamodb_billing  = "PAY_PER_REQUEST"
      enable_cdn        = false
      retention_in_days = 180
    }
    staging = {
      lambda_memory     = 256
      lambda_timeout    = 60
      dynamodb_billing  = "PAY_PER_REQUEST"
      enable_cdn        = true
      retention_in_days = 180
    }
    prod = {
      lambda_memory     = 512
      lambda_timeout    = 60
      dynamodb_billing  = "PAY_PER_REQUEST"
      enable_cdn        = true
      retention_in_days = 365
    }
  }

  config = local.environment_config[var.environment]

  # Resource naming convention (demonstrates operational standards)
  name_prefix = "${var.project_name}-${var.environment}"

  # Common tags applied to all resources (demonstrates cost management)
  common_tags = merge(
    {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "terraform"
      Repository  = "cloud-resume-challenge"
      Owner       = "ricardo-torres"
      CostCenter  = "personal-development"
      LastUpdated = timestamp()
    },
    var.cost_allocation_tags
  )
}

# Data sources for account information

data "aws_region" "current" {}
