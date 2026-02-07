output "config_arn" {
  description = "The ARN of the AWS Config rule for tagging compliance."
  value       = aws_config_config_rule.tagging_compliance.arn
}

output "lambda_arn" {
  description = "The ARN of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_arn
}