
## Craft a custom policy for the lambda function
data "aws_iam_policy_document" "permissions" {
  statement {
    sid    = "AllowDynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Put*",
      "dynamodb:Scan*",
    ]
    resources = [
      var.dynamodb_table_arn
    ]
  }

  statement {
    sid    = "AllowOrganizations"
    effect = "Allow"
    actions = [
      "organizations:List*",
      "organizations:Describe*",
    ]
    resources = ["*"]
  }
}

## Lambda function that used to handle the aws config rule
module "lambda_function" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.2.0"

  function_name                = var.lambda_name
  function_tags                = var.tags
  description                  = var.lambda_description
  handler                      = "handler.lambda_handler"
  hash_extra                   = var.lambda_name
  memory_size                  = var.lambda_memory_size
  runtime                      = var.lambda_runtime
  source_path                  = "${path.module}/assets/handler.py"
  tags                         = merge(var.tags, { "Name" = var.lambda_name })
  timeout                      = var.lambda_timeout
  trigger_on_package_timestamp = false

  ## Environment variables for the Lambda function
  environment_variables = {
    DYNAMODB_TABLE_ARN = var.dynamodb_table_arn
    LOG_LEVEL          = var.lambda_log_level
  }

  ## Lambda Role
  create_role                   = true
  role_name                     = var.lambda_name
  role_tags                     = var.tags
  role_force_detach_policies    = true
  role_permissions_boundary     = null
  role_maximum_session_duration = 3600
  role_path                     = "/"

  ## IAM Policy
  attach_policy_json            = true
  attach_network_policy         = false
  attach_cloudwatch_logs_policy = true
  attach_tracing_policy         = true
  policy_json                   = data.aws_iam_policy_document.permissions.json

  ## Cloudwatch Logs 
  cloudwatch_logs_tags              = var.tags
  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
}

## Provision a permission to allow aws events to invoke the lambda function
resource "aws_cloudwatch_event_rule" "scheduled_sync" {
  count = var.enable_scheduled_sync ? 1 : 0

  name                = var.scheduled_sync_rule_name
  description         = "Periodic run the AWS Organizations handler used by the tagging compliance solution."
  schedule_expression = var.scheduled_sync_expression
  tags                = var.tags
}

## Provision a permission to allow aws events to invoke the lambda function
resource "aws_cloudwatch_event_target" "scheduled_sync" {
  count = var.enable_scheduled_sync ? 1 : 0

  rule      = aws_cloudwatch_event_rule.scheduled_sync[0].name
  target_id = "OrganizationsInventoryScheduledSync"
  arn       = module.lambda_function.lambda_function_arn
}

## Provision a permission to allow scheduled events to invoke the lambda function
resource "aws_lambda_permission" "allow_scheduled_events" {
  count = var.enable_scheduled_sync ? 1 : 0

  action        = "lambda:InvokeFunction"
  function_name = module.lambda_function.lambda_function_name
  principal     = "events.amazonaws.com"
  statement_id  = "AllowExecutionFromScheduledEvents"
  source_arn    = aws_cloudwatch_event_rule.scheduled_sync[0].arn
}

## Provision a permission to allow account events to invoke the lambda function
resource "aws_cloudwatch_event_rule" "account_events" {
  count = var.enable_account_event_sync ? 1 : 0

  name          = var.account_event_rule_name
  description   = "Trigger AWS Organizations handler on account creation/closure events for the tagging compliance solution."
  event_pattern = local.accounts_event_pattern
  tags          = var.tags
}

## Provision a permission to allow account events to invoke the lambda function
resource "aws_cloudwatch_event_target" "account_events" {
  count = var.enable_account_event_sync ? 1 : 0

  rule      = aws_cloudwatch_event_rule.account_events[0].name
  target_id = "OrganizationsInventoryAccountEvents"
  arn       = module.lambda_function.lambda_function_arn
}

## Provision a permission to allow account events to invoke the lambda function
resource "aws_lambda_permission" "allow_account_events" {
  count = var.enable_account_event_sync ? 1 : 0

  action        = "lambda:InvokeFunction"
  function_name = module.lambda_function.lambda_function_name
  principal     = "events.amazonaws.com"
  statement_id  = "AllowExecutionFromAccountEvents"
  source_arn    = aws_cloudwatch_event_rule.account_events[0].arn
}