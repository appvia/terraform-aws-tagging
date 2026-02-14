
## Provision the custom lambda function
module "lambda_function" {
  source = "../validation"

  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  dynamodb_table_arn                = var.dynamodb_table_arn
  lambda_create_role                = var.lambda_create_role
  lambda_description                = var.lambda_description
  lambda_log_level                  = var.lambda_log_level
  lambda_memory_size                = var.lambda_memory_size
  lambda_name                       = var.lambda_name
  lambda_role_name                  = var.lambda_role_name
  lambda_runtime                    = var.lambda_runtime
  lambda_timeout                    = var.lambda_timeout
  organizations_table_arn           = var.organizations_table_arn
  rules_cache_enabled               = var.rules_cache_enabled
  rules_cache_ttl_seconds           = var.rules_cache_ttl_seconds
  tags                              = var.tags
}

## Provision a custom aws config rule to invoke the lambda function for tagging compliance
resource "aws_config_config_rule" "tagging_compliance" {
  name        = var.config_name
  description = "Custom AWS Config rule to evaluate tagging compliance using a Lambda function."

  scope {
    compliance_resource_types = var.config_resource_types
  }

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = module.lambda_function.lambda_arn

    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }

  depends_on = [
    module.lambda_function,
  ]
}

