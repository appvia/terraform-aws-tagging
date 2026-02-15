output "compliance_rule_table_arn" {
  description = "The ARN of the DynamoDB table used for tagging compliance."
  value       = aws_dynamodb_table.compliance.arn
}

output "compliance_rule_table_name" {
  description = "The name of the DynamoDB table used for tagging compliance."
  value       = aws_dynamodb_table.compliance.name
}

output "organizations_id" {
  description = "The ID of the AWS Organization allowed access to the DynamoDB table."
  value       = local.organizations_id
}

output "organizations_table_arn" {
  description = "The ARN of the DynamoDB table used for storing organization metadata."
  value       = try(aws_dynamodb_table.organizations[0].arn, null)
}

output "organizations_table_name" {
  description = "The name of the DynamoDB table used for storing organization metadata."
  value       = try(aws_dynamodb_table.organizations[0].name, null)
}

output "organizations_lambda_arn" {
  description = "The ARN of the Lambda function used for handling organization account movements."
  value       = try(module.organizations_handler[0].lambda_arn, null)
}

output "organizations_lambda_name" {
  description = "The name of the Lambda function used for handling organization account movements."
  value       = try(module.organizations_handler[0].lambda_name, null)
}
