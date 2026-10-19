variable "account_event_rule_name" {
  description = "Name of the EventBridge rule used for account event syncs."
  type        = string
  default     = "organizations-account-inventory-account-events"
}

variable "accounts_key" {
  description = "The object key of the account inventory (YAML) written to the bucket."
  type        = string
  default     = "accounts.yaml"
}

variable "bucket_arn" {
  description = "The ARN of the S3 bucket the account inventory is written to."
  type        = string
}

variable "bucket_name" {
  description = "The name of the S3 bucket the account inventory is written to."
  type        = string
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

variable "conformance_pack_name" {
  description = "The name of the organization conformance pack to re-put with a new InventoryVersion when the inventory changes, forcing an org-wide re-evaluation. Requires conformance_pack_template_uri. When null, no re-evaluation is triggered."
  type        = string
  default     = null
}

variable "conformance_pack_template_uri" {
  description = "The S3 URI (s3://bucket/key) of the conformance pack template (pack module output s3_template_uri). Required with conformance_pack_name because DescribeOrganizationConformancePacks does not return the template location."
  type        = string
  default     = null

  validation {
    condition     = var.conformance_pack_template_uri == null || can(regex("^s3://[^/]+/.+$", var.conformance_pack_template_uri))
    error_message = "conformance_pack_template_uri must be an S3 URI of the form s3://bucket/key."
  }
}

variable "enable_account_event_sync" {
  description = "Enable an EventBridge rule to trigger the sync on account create, close, move, tag and untag events (Organizations CloudTrail events are delivered to EventBridge in us-east-1 only)."
  type        = bool
  default     = false
}

variable "enable_scheduled_sync" {
  description = "Enable a scheduled EventBridge rule to trigger the sync periodically."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key encrypting the bucket. When set, the lambda is granted kms:Decrypt and kms:GenerateDataKey on it."
  type        = string
  default     = null
}

variable "lambda_description" {
  description = "The description of the Lambda function to synchronize AWS Organizations account information."
  type        = string
  default     = "Synchronizes AWS Organizations account information to S3."
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
