
## Provision the custom lambda function
module "lambda_function" {
  source = "../validation"

  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  dynamodb_table_arn                = var.dynamodb_table_arn
  lambda_description                = var.lambda_description
  lambda_log_level                  = var.lambda_log_level
  lambda_name                       = var.lambda_name
  lambda_role_name                  = var.lambda_role_name
  lambda_runtime                    = var.lambda_runtime
  lambda_timeout                    = var.lambda_timeout
  tags                              = var.tags
}

## Provision a permission to allow aws config to invoke the lambda function
resource "aws_lambda_permission" "allow_config" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_function.lambda_name
  principal     = "config.amazonaws.com"
  statement_id  = "AllowExecutionFromConfig"
  source_arn    = "arn:aws:config:*:${local.account_id}:config-rule/${var.config_name}"
}

## Provision a custom aws config rule to invoke the lambda function for tagging compliance
resource "aws_config_config_rule" "tagging_compliance" {
  name                        = var.config_name
  description                 = "Custom AWS Config rule to evaluate tagging compliance using a Lambda function."
  maximum_execution_frequency = var.config_max_execution_frequency

  scope {
    compliance_resource_types = var.config_resource_types
  }

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = module.lambda_function.lambda_arn
  }

  depends_on = [
    aws_lambda_permission.allow_config,
  ]
}