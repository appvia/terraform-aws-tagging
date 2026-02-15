variable "allowed_source_accounts" {
  description = "List of AWS account IDs allowed to invoke this Lambda function. If not provided and organization_id is set, allows all accounts in the organization."
  type        = list(string)
  default     = []
}

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

variable "organizations_id" {
  description = "AWS Organization ID to allow cross-account invocation."
  type        = string
  default     = null
}

variable "organizations_table_arn" {
  description = "The ARN of the DynamoDB table to store AWS Organizations account information. "
  type        = string
  default     = null
}

variable "rules_cache_enabled" {
  description = "Enable or disable caching of compliance rules in Lambda function memory."
  type        = bool
  default     = true
}

variable "rules_cache_ttl_seconds" {
  description = "Time-to-live (TTL) in seconds for cached compliance rules."
  type        = number
  default     = 300
}

variable "tags" {
  description = "A map of tags to apply to the Lambda function."
  type        = map(string)
  default     = {}
}
