
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