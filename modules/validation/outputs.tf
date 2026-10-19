output "lambda_arn" {
  description = "The ARN of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_arn
}

output "lambda_name" {
  description = "The name of the Lambda function for tagging compliance."
  value       = module.lambda_function.lambda_function_name
}

output "environment_variables" {
  description = "The environment variables configured on the Lambda function (policy bucket, object keys, cache and log settings)."
  value       = local.environment_variables
}
