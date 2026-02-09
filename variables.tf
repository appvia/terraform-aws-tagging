variable "compliance" {
  description = "Configuration for the compliance feature."
  type = object({
    table = object({
      ## The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY_PER_REQUEST.
      billing_mode = optional(string, "PAY_PER_REQUEST")
      ## The KMS key ID or ARN to use for server-side encryption of the DynamoDB table.
      kms_key_id = optional(string, null)
      ## The name of the DynamoDB table to store compliance rules.
      name = optional(string, "tagging-compliance")
      ## Whether to enable point-in-time recovery for the DynamoDB table. Defaults to false.
      point_in_time_recovery_enabled = optional(bool, false)
      ## The read capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).
      read_capacity = optional(number, null)
      ## The write capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).
      write_capacity = optional(number, null)
    })
  })
  default = {
    table = {}
  }
}

variable "organizations" {
  description = "Configuration for the organizations table and lambda."
  type = object({
    table = object({
      ## The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY_PER_REQUEST.
      billing_mode = optional(string, "PAY_PER_REQUEST")
      ## The KMS key ID or ARN to use for server-side encryption of the DynamoDB table.
      kms_key_id = optional(string, null)
      ## The name of the DynamoDB table to store organization metadata for AWS resources.
      name = optional(string, "organization-compliance")
      ## Whether to enable point-in-time recovery for the DynamoDB table. Defaults to false.
      point_in_time_recovery_enabled = optional(bool, false)
      ## The read capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).
      read_capacity = optional(number, null)
      ## The write capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).
      write_capacity = optional(number, null)
    }),
    lambda = optional(object({
      ## The description of the Lambda function to handle AWS Organization account movements.
      description = optional(string, "Handles AWS Organization account movements for tagging compliance.")
      ## The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL.
      log_level = optional(string, "INFO")
      ## The amount of memory in MB allocated to the Lambda function.
      memory_size = optional(number, 128)
      ## The name of the Lambda function to handle AWS Organization account movements.
      name = optional(string, "organization-compliance")
      ## The runtime environment for the Lambda function.
      runtime = optional(string, "python3.12")
      ## The timeout for the Lambda function in seconds.
      timeout = optional(number, 30)
    }), {})
  })
  default = null
}

variable "enable_organizations" {
  description = "Enable organization access to the DynamoDB table. When enabled, allows any account in the organization to access the table."
  type        = bool
  default     = true
}

variable "organizations_id" {
  description = "AWS Organization ID to allow access to the DynamoDB table/s"
  type        = string
  default     = null
}

variable "rules" {
  description = "List of compliance rules to be stored in the DynamoDB table."
  type = list(object({
    AccountIds          = optional(list(string), [])
    Enabled             = optional(bool, true)
    Required            = optional(bool, true)
    ResourceTypes       = list(string)
    RuleId              = string
    Tag                 = string
    ValuePattern        = optional(string, null)
    Values              = optional(list(string), [])
    OrganizationalPaths = optional(list(string), [])
  }))
  default = []
}

variable "tags" {
  description = "A map of tags to apply to the DynamoDB table."
  type        = map(string)
  default     = {}
}