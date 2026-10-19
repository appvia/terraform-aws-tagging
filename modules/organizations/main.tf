
## Craft a custom policy for the lambda function
data "aws_iam_policy_document" "permissions" {
  statement {
    sid    = "AllowInventoryReadWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      format("%s/%s", var.bucket_arn, var.accounts_key),
    ]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []

    content {
      sid    = "AllowInventoryEncryption"
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey",
      ]
      resources = [var.kms_key_arn]
    }
  }

  statement {
    sid    = "AllowOrganizations"
    effect = "Allow"
    actions = [
      "organizations:List*",
      "organizations:Describe*",
      "organizations:ListTagsForResource",
    ]
    resources = ["*"]
  }

  ## Re-putting the organization conformance pack when the inventory changes. Permissions
  ## per the AWS Config API reference for PutOrganizationConformancePack
  ## (https://docs.aws.amazon.com/config/latest/APIReference/API_PutOrganizationConformancePack.html):
  ## the call enables service access for config-multiaccountsetup.amazonaws.com
  ## (organizations:EnableAWSServiceAccess), creates the AWSServiceRoleForConfigMultiAccountSetup
  ## service-linked role when missing (iam:GetRole / iam:CreateServiceLinkedRole), needs
  ## ListDelegatedAdministrators (and RegisterDelegatedAdministrator for delegated admin setups),
  ## reads the organization and its accounts, and the caller must be able to read the template
  ## object in S3.
  dynamic "statement" {
    for_each = var.conformance_pack_name != null ? [1] : []

    content {
      sid    = "AllowConformancePackUpdate"
      effect = "Allow"
      actions = [
        "config:DescribeOrganizationConformancePacks",
        "config:PutOrganizationConformancePack",
        "organizations:DescribeOrganization",
        "organizations:EnableAWSServiceAccess",
        "organizations:ListAccounts",
        "organizations:ListDelegatedAdministrators",
        "organizations:RegisterDelegatedAdministrator",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.conformance_pack_name != null ? [1] : []

    content {
      sid     = "AllowConformancePackServiceLinkedRole"
      effect  = "Allow"
      actions = ["iam:CreateServiceLinkedRole"]
      resources = [
        format("arn:%s:iam::*:role/aws-service-role/config-multiaccountsetup.amazonaws.com/*", data.aws_partition.current.partition),
      ]

      condition {
        test     = "StringEquals"
        variable = "iam:AWSServiceName"
        values   = ["config-multiaccountsetup.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.conformance_pack_name != null ? [1] : []

    content {
      sid     = "AllowConformancePackServiceLinkedRoleRead"
      effect  = "Allow"
      actions = ["iam:GetRole"]
      resources = [
        format("arn:%s:iam::*:role/aws-service-role/config-multiaccountsetup.amazonaws.com/*", data.aws_partition.current.partition),
      ]
    }
  }

  dynamic "statement" {
    for_each = var.conformance_pack_name != null && var.conformance_pack_template_uri != null ? [1] : []

    content {
      sid       = "AllowConformancePackTemplateRead"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = [local.conformance_pack_template_arn]
    }
  }
}

## Lambda function that used to handle the aws config rule
module "lambda_function" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.9.0"

  function_name = var.lambda_name
  function_tags = var.tags
  description   = var.lambda_description
  handler       = "handler.lambda_handler"
  hash_extra    = var.lambda_name
  memory_size   = var.lambda_memory_size
  runtime       = var.lambda_runtime
  source_path = [
    {
      path             = "${path.module}/assets"
      pip_requirements = true
      patterns         = ["!.*_test\\.py", "!testdata/.*", "!__pycache__/.*"]
    }
  ]
  tags                         = merge(var.tags, { "Name" = var.lambda_name })
  timeout                      = var.lambda_timeout
  trigger_on_package_timestamp = false

  ## Environment variables for the Lambda function
  environment_variables = merge({
    ACCOUNTS_KEY = var.accounts_key
    BUCKET_NAME  = var.bucket_name
    LOG_LEVEL    = var.lambda_log_level
  }, local.conformance_pack_environment)

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
  description   = "Trigger AWS Organizations handler on account create, close, move, tag and untag events for the tagging compliance solution."
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