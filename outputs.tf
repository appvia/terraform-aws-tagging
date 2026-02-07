output "dynamodb_arn" {
  description = "The ARN of the DynamoDB table used for tagging compliance."
  value       = aws_dynamodb_table.compliance.arn
}

output "dynamodb_name" {
  description = "The name of the DynamoDB table used for tagging compliance."
  value       = aws_dynamodb_table.compliance.name
}

output "organization_id" {
  description = "The ID of the AWS Organization allowed access to the DynamoDB table."
  value       = local.organization_id
}