variable "cloudwatch_logs_kms_key_id" {
  description = "The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted."
  type        = string
  default     = null
}

variable "cloudwatch_logs_log_group_class" {
  description = "The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT_ACCESS."
  type        = string
  default     = "STANDARD"
}

variable "cloudwatch_logs_retention_in_days" {
  description = "The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827."
  type        = number
  default     = 7
}

variable "dynamodb_table_arn" {
  description = "The ARN of the DynamoDB table to store tags for AWS resources."
  type        = string
}

variable "config_name" {
  description = "The name of the AWS Config rule"
  type        = string
  default     = "tagging-compliance"
}

variable "config_resource_types" {
  description = "List of AWS resource types to evaluate (https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html)"
  type        = list(string)
}

variable "lambda_architectures" {
  description = "The lambda architecture to use. Valid values are x86_64 and arm64."
  type        = list(string)
  default     = ["arm64", "x86_64"]
}

variable "lambda_create_role" {
  description = "Indicates we should create the role"
  type        = bool
  default     = true
}

variable "lambda_description" {
  description = "The description of the Lambda function to handle AWS Organization account movements."
  type        = string
  default     = "Handles AWS Organization account movements for tagging compliance."
}

variable "lambda_log_level" {
  description = "The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL."
  type        = string
  default     = "INFO"
}

variable "lambda_memory_size" {
  description = "The amount of memory in MB allocated to the Lambda function."
  type        = number
  default     = 128
}

variable "lambda_name" {
  description = "The name of the Lambda function to handle AWS Organization account movements."
  type        = string
  default     = "lz-tagging-compliance"
}

variable "lambda_role_name" {
  description = "The name of the IAM role to be created for the Lambda function."
  type        = string
  default     = "lz-tagging-compliance"
}

variable "lambda_runtime" {
  description = "The runtime environment for the Lambda function."
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "The timeout for the Lambda function in seconds."
  type        = number
  default     = 30
}

variable "organizations_table_arn" {
  description = "The ARN of the DynamoDB table to store AWS Organizations account information."
  type        = string
  default     = null
}

variable "rules_cache_enabled" {
  description = "Enable or disable caching of compliance rules in Lambda function memory. When enabled, rules are cached between invocations to reduce DynamoDB read costs and improve performance."
  type        = bool
  default     = true
}

variable "rules_cache_ttl_seconds" {
  description = "Time-to-live (TTL) in seconds for cached compliance rules. After this period, the cache expires and rules are re-fetched from DynamoDB. Default is 300 seconds (5 minutes)."
  type        = number
  default     = 300

  validation {
    condition     = var.rules_cache_ttl_seconds >= 0
    error_message = "Cache TTL must be between 0"
  }
}

variable "tags" {
  description = "A map of tags to apply to the Lambda function."
  type        = map(string)
  default     = {}
}
