output "account_event_pattern" {
  description = "The EventBridge event pattern of the account event rule, or null when the account event sync is disabled."
  value       = try(aws_cloudwatch_event_rule.account_events[0].event_pattern, null)
}

output "lambda_arn" {
  description = "The ARN of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_arn
}

output "lambda_name" {
  description = "The name of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_name
}
