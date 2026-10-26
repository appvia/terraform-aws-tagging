variable "accounts_key" {
  description = "The object key of the account inventory in the policy bucket. When null, no inventory is read and organizational_path/account_tag rules are ignored."
  type        = string
  default     = null
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

variable "config_name" {
  description = "The name of the AWS Config rule"
  type        = string
  default     = "tagging-compliance"
}

variable "config_resource_types" {
  description = "List of AWS resource types to evaluate (https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html)"
  type        = list(string)
}

variable "configuration_item_change_enabled" {
  description = "When true, the rule is invoked when AWS Config records a configuration change (including oversized configuration notifications) for resources in scope. Set to false and enable periodic_evaluation_enabled to run only on a schedule."
  type        = bool
  default     = true
}

variable "maximum_execution_frequency" {
  description = "Maximum interval between periodic evaluations when periodic_evaluation_enabled is true. Values: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.maximum_execution_frequency)
    error_message = "maximum_execution_frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "periodic_evaluation_enabled" {
  description = "When true, AWS Config also invokes the rule on a recurring schedule; use maximum_execution_frequency to set how often. Combine with configuration_item_change_enabled for both change-driven and scheduled evaluations."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key encrypting the policy bucket. When set, the lambda is granted kms:Decrypt on it."
  type        = string
  default     = null
}

variable "lambda_architectures" {
  description = "The lambda architecture to use. Valid values are x86_64 and arm64."
  type        = list(string)
  default     = ["arm64"]
}

variable "lambda_artifacts_dir" {
  description = "The directory to store any generated artifacts for the lambda"
  type        = string
  default     = "builds"
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
  default     = "python3.14"
}

variable "lambda_timeout" {
  description = "The timeout for the Lambda function in seconds."
  type        = number
  default     = 30
}

variable "mappings_key" {
  description = "The object key of the resource type mappings in the policy bucket."
  type        = string
  default     = "mappings.yaml"
}

variable "mappings_version" {
  description = "A hash of the mappings content (root module output mappings_version). Changing it forces AWS Config to re-evaluate all resources."
  type        = string
}

variable "policy_bucket_arn" {
  description = "The ARN of the S3 bucket holding the tagging policy, mappings and inventory."
  type        = string
}

variable "policy_bucket_name" {
  description = "The name of the S3 bucket holding the tagging policy, mappings and inventory."
  type        = string
}

variable "policy_key" {
  description = "The object key of the tagging policy in the policy bucket."
  type        = string
  default     = "policy.yaml"
}

variable "policy_version" {
  description = "A hash of the tagging policy content (root module output policy_version). Changing it forces AWS Config to re-evaluate all resources."
  type        = string
}

variable "rules_cache_enabled" {
  description = "Enable or disable caching of compliance rules in Lambda function memory. When enabled, the policy, mappings and inventory are cached between invocations to reduce S3 reads and improve performance."
  type        = bool
  default     = true
}

variable "rules_cache_ttl_seconds" {
  description = "Time-to-live (TTL) in seconds for the cached policy, mappings and inventory. After this period, the cached objects are revalidated against S3. Default is 300 seconds (5 minutes)."
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
