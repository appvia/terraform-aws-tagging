
## Provision the custom lambda function
module "lambda_function" {
  source = "../validation"

  accounts_key                      = var.accounts_key
  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  kms_key_arn                       = var.kms_key_arn
  lambda_architectures              = var.lambda_architectures
  lambda_artifacts_dir              = var.lambda_artifacts_dir
  lambda_create_role                = var.lambda_create_role
  lambda_description                = var.lambda_description
  lambda_log_level                  = var.lambda_log_level
  lambda_memory_size                = var.lambda_memory_size
  lambda_name                       = var.lambda_name
  lambda_role_name                  = var.lambda_role_name
  lambda_runtime                    = var.lambda_runtime
  lambda_timeout                    = var.lambda_timeout
  mappings_key                      = var.mappings_key
  policy_bucket_arn                 = var.policy_bucket_arn
  policy_bucket_name                = var.policy_bucket_name
  policy_key                        = var.policy_key
  rules_cache_enabled               = var.rules_cache_enabled
  rules_cache_ttl_seconds           = var.rules_cache_ttl_seconds
  tags                              = var.tags
}

## Provision a custom aws config rule to invoke the lambda function for tagging compliance
resource "aws_config_config_rule" "tagging_compliance" {
  name        = var.config_name
  description = "Custom AWS Config rule to evaluate tagging compliance using a Lambda function."

  ## The version hashes only force a re-evaluation when the policy or mappings change;
  ## the lambda reads the policy location from its environment
  input_parameters = jsonencode({
    PolicyVersion   = var.policy_version
    MappingsVersion = var.mappings_version
  })

  scope {
    compliance_resource_types = var.config_resource_types
  }

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = module.lambda_function.lambda_arn

    dynamic "source_detail" {
      for_each = var.configuration_item_change_enabled ? [1] : []
      content {
        event_source = "aws.config"
        message_type = "ConfigurationItemChangeNotification"
      }
    }
    dynamic "source_detail" {
      for_each = var.configuration_item_change_enabled ? [1] : []
      content {
        event_source = "aws.config"
        message_type = "OversizedConfigurationItemChangeNotification"
      }
    }
    dynamic "source_detail" {
      for_each = var.periodic_evaluation_enabled ? [1] : []
      content {
        event_source                = "aws.config"
        message_type                = "ScheduledNotification"
        maximum_execution_frequency = var.maximum_execution_frequency
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.configuration_item_change_enabled || var.periodic_evaluation_enabled
      error_message = "At least one of configuration_item_change_enabled or periodic_evaluation_enabled must be true."
    }
  }

  depends_on = [
    module.lambda_function,
  ]
}

