
variable "dynamodb_billing_mode" {
  description = "The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY_PER_REQUEST."
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "dynamodb_table_name" {
  description = "The name of the DynamoDB table to store tags for AWS resources."
  type        = string
  default     = "tagging-compliance"
}

variable "dynamodb_table_kms_key_id" {
  description = "KMS key ID for DynamoDB table encryption (optional)"
  type        = string
  default     = null
}

variable "dynamodb_table_point_in_time_recovery_enabled" {
  description = "Enable point-in-time recovery for the DynamoDB table"
  type        = bool
  default     = false
}

variable "dynamodb_table_read_capacity" {
  description = "The read capacity units for the DynamoDB table (only applicable if billing mode is PROVISIONED)"
  type        = number
  default     = null
}

variable "dynamodb_table_write_capacity" {
  description = "The write capacity units for the DynamoDB table (only applicable if billing mode is PROVISIONED)"
  type        = number
  default     = null
}

variable "enable_organization_access" {
  description = "Whether to allow access to the DynamoDB table from the AWS Organization."
  type        = bool
  default     = true
}

variable "organization_id" {
  description = "The ID of the AWS Organization to allow access to the DynamoDB table."
  type        = string
  default     = null
}

variable "rules" {
  description = "List of compliance rules to be stored in the DynamoDB table."
  type = list(object({
    AccountIds   = optional(list(string), ["*"])
    Enabled      = optional(bool, true)
    Required     = optional(bool, true)
    ResourceType = string
    RuleId       = string
    Tag          = string
    ValuePattern = optional(string, null)
    Values       = optional(list(string), [])
  }))
  default = []
}

variable "tags" {
  description = "A map of tags to apply to the DynamoDB table."
  type        = map(string)
  default     = {}
}