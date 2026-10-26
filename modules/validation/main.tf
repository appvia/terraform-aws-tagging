
## Craft a custom policy for the lambda function
data "aws_iam_policy_document" "permissions" {
  statement {
    sid       = "AllowPolicyRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [for key in local.object_keys : format("%s/%s", var.policy_bucket_arn, key)]
  }

  ## Without s3:ListBucket a missing object (e.g. the inventory before the first sync)
  ## returns AccessDenied rather than NoSuchKey
  statement {
    sid       = "AllowPolicyBucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [var.policy_bucket_arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []

    content {
      sid       = "AllowPolicyDecrypt"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }

  statement {
    sid       = "AllowConfigPutEvents"
    effect    = "Allow"
    actions   = ["config:Put*"]
    resources = ["*"]
  }
}

## Lambda function that used to handle the aws config rule
module "lambda_function" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.12.0"

  architectures = var.lambda_architectures
  artifacts_dir = var.lambda_artifacts_dir
  function_name = var.lambda_name
  function_tags = var.tags
  description   = var.lambda_description
  handler       = "handler.lambda_handler"
  hash_extra    = "tagging_compliance"
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
  environment_variables = local.environment_variables

  ## Lambda Role
  create_role                   = var.lambda_create_role
  role_name                     = var.lambda_role_name
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

## Provision a permission to allow aws config to invoke the lambda function
resource "aws_lambda_permission" "allow_config" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_function.lambda_function_name
  principal     = "config.amazonaws.com"
  statement_id  = "AllowExecutionFromConfig"
  # For same-account deployment, no source_account restriction needed
  # For cross-account deployment, specify source accounts or organization
  source_account = var.organizations_id != null ? null : local.account_id
}

## Allow cross-account invocation from organization accounts
resource "aws_lambda_permission" "allow_organization" {
  count = var.organizations_id != null ? 1 : 0

  action           = "lambda:InvokeFunction"
  function_name    = module.lambda_function.lambda_function_name
  principal        = "config.amazonaws.com"
  principal_org_id = var.organizations_id
  statement_id     = "AllowExecutionFromOrganization"
}

## Allow invocation from specific accounts (if provided)
resource "aws_lambda_permission" "allow_specific_accounts" {
  for_each = toset(var.allowed_source_accounts)

  action         = "lambda:InvokeFunction"
  function_name  = module.lambda_function.lambda_function_name
  principal      = "config.amazonaws.com"
  statement_id   = "AllowExecutionFromAccount${each.key}"
  source_account = each.key
}

