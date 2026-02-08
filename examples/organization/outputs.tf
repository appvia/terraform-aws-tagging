output "dynamodb_table_arn" {
  description = "The ARN of the DynamoDB table used for tagging compliance."
  value       = module.compliance.dynamodb_table_arn
}

output "organizations_table_arn" {
  description = "The ARN of the DynamoDB table used for storing organization metadata."
  value       = module.compliance.organizations_table_arn
}