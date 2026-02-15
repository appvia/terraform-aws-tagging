variable "compliance_rule_table_arn" {
  description = "The ARN of the DynamoDB table to store tags for AWS resources."
  type        = string
}

variable "organizations_table_arn" {
  description = "The ARN of the DynamoDB table to store organization metadata."
  type        = string
}

