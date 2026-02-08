variable "account_event_rule_name" {
  description = "Name of the EventBridge rule used for account event syncs."
  type        = string
  default     = "organizations-account-inventory-account-events"
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
  description = "The ARN of the DynamoDB table to store AWS Organizations account information."
  type        = string
}

variable "enable_account_event_sync" {
  description = "Enable an EventBridge rule to trigger the sync on account creation/closure events."
  type        = bool
  default     = false
}

variable "enable_scheduled_sync" {
  description = "Enable a scheduled EventBridge rule to trigger the sync periodically."
  type        = bool
  default     = true
}

variable "lambda_description" {
  description = "The description of the Lambda function to synchronize AWS Organizations account information."
  type        = string
  default     = "Synchronizes AWS Organizations account information to DynamoDB."
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
  description = "The name of the Lambda function to synchronize AWS Organizations account information."
  type        = string
  default     = "organizations-account-inventory"
}

variable "lambda_runtime" {
  description = "The runtime environment for the Lambda function."
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "The timeout for the Lambda function in seconds."
  type        = number
  default     = 60
}

variable "scheduled_sync_expression" {
  description = "EventBridge schedule expression for periodic sync (e.g., rate(1 day), cron(0 2 * * ? *))."
  type        = string
  default     = "rate(1 day)"
}

variable "scheduled_sync_rule_name" {
  description = "Name of the EventBridge rule used for scheduled syncs."
  type        = string
  default     = "organizations-account-inventory-schedule"
}

variable "tags" {
  description = "A map of tags to apply to the Lambda function."
  type        = map(string)
  default     = {}
}
