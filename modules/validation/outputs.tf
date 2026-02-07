output "lambda_arn" {
  description = "The ARN of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_arn
}

output "lambda_name" {
  description = "The name of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_name
}