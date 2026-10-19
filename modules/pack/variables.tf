variable "accounts_key" {
  description = "The object key of the account inventory in the policy bucket. When null, no inventory is read and organizational_path/account_tag rules are ignored."
  type        = string
  default     = null
}

variable "conformance_pack_name" {
  description = "Name of the AWS Config Conformance Pack"
  type        = string
  default     = "tagging-compliance"
}

variable "config_rule_name" {
  description = "Name of the AWS Config rule within the conformance pack"
  type        = string
  default     = "tagging-compliance"
}

variable "cloudwatch_logs_kms_key_id" {
  description = "KMS key ID for encrypting CloudWatch Logs (optional)"
  type        = string
  default     = null
}

variable "cloudwatch_logs_log_group_class" {
  description = "Log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT_ACCESS."
  type        = string
  default     = "STANDARD"
}

variable "cloudwatch_logs_retention_in_days" {
  description = "Number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827."
  type        = number
  default     = 7
}

variable "deploy_organization_wide" {
  description = "Whether to deploy the conformance pack organization-wide (requires Organizations management account)"
  type        = bool
  default     = false
}

variable "excluded_accounts" {
  description = "List of AWS account IDs to exclude from organization conformance pack deployment"
  type        = list(string)
  default     = []
}

variable "input_parameters" {
  description = "Map of additional input parameters to pass to the conformance pack. PolicyVersion and MappingsVersion are always set from policy_version and mappings_version; InventoryVersion is read from the content-sha256 metadata of the inventory object (or none)."
  type        = map(string)
  default     = {}
}

variable "inventory_version" {
  description = "Pin the InventoryVersion pack parameter instead of reading the content-sha256 metadata of the inventory object. When set, no S3 data sources are read. Bootstrap: pass \"none\" on the first apply when the policy bucket is created in the same configuration (the bucket does not exist at plan time), then remove it so the version follows the inventory."
  type        = string
  default     = null
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key encrypting the policy bucket. When set, the lambda is granted kms:Decrypt on it."
  type        = string
  default     = null
}

variable "lambda_function_arn" {
  description = "ARN of the Lambda function that evaluates compliance"
  type        = string
  default     = null
}

variable "mappings_key" {
  description = "The object key of the resource type mappings in the policy bucket."
  type        = string
  default     = "mappings.yaml"
}

variable "mappings_version" {
  description = "A hash of the mappings content (root module output mappings_version), passed as the MappingsVersion pack parameter to force re-evaluation on change."
  type        = string
}

variable "max_execution_frequency" {
  description = "Maximum frequency for Config rule evaluation"
  type        = string
  default     = "TwentyFour_Hours"
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.max_execution_frequency)
    error_message = "max_execution_frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours"
  }
}

variable "pack_description" {
  description = "Description of the conformance pack"
  type        = string
  default     = "AWS Config Conformance Pack for validating resource tagging compliance"
}

variable "policy_bucket_arn" {
  description = "The ARN of the S3 bucket holding the tagging policy, mappings and inventory. Required unless lambda_function_arn is provided."
  type        = string
  default     = null
}

variable "policy_bucket_name" {
  description = "The name of the S3 bucket holding the tagging policy, mappings and inventory. Required unless lambda_function_arn is provided."
  type        = string
  default     = null
}

variable "policy_key" {
  description = "The object key of the tagging policy in the policy bucket."
  type        = string
  default     = "policy.yaml"
}

variable "policy_version" {
  description = "A hash of the tagging policy content (root module output policy_version), passed as the PolicyVersion pack parameter to force re-evaluation on change."
  type        = string
}

variable "resource_types" {
  description = "List of AWS resource types to evaluate (e.g., AWS::EC2::Instance)"
  type        = list(string)
  default     = ["AWS::*"]
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket to store the conformance pack template"
  type        = string
}

variable "s3_enable_versioning" {
  description = "Enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "s3_kms_key_id" {
  description = "KMS key ID for S3 bucket encryption (optional)"
  type        = string
  default     = null
}

variable "s3_template_key" {
  description = "S3 object key for the conformance pack template"
  type        = string
  default     = "conformance-packs/tagging-compliance.yaml"
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
