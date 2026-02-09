
variable "dynamodb_table_name" {
  description = "The name of the DynamoDB table to store tags for AWS resources."
  type        = string
}

variable "rules" {
  description = "List of compliance rules to be stored in the DynamoDB table."
  type = list(object({
    AccountIds          = optional(list(string), ["*"])
    Enabled             = optional(bool, true)
    OrganizationalPaths = optional(list(string), [])
    Required            = optional(bool, true)
    ResourceTypes       = list(string)
    RuleId              = string
    Tag                 = string
    ValuePattern        = optional(string, "")
    Values              = optional(list(string), [])
  }))
}