locals {
  ## Indicates if organizations handler is enables 
  enable_organizations = var.organizations != null
}

## Update the DynamoDB policy permitting access to the table from the organization
data "aws_iam_policy_document" "organizations_access" {

  statement {
    sid    = "AllowOrganizationAccessToDynamoDBTable"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = [
      format("arn:aws:dynamodb:%s:%s:table/%s", local.region, local.account_id, try(var.organizations.table.name, "organization-compliance"))
    ]

    dynamic "condition" {
      for_each = local.enable_organizations ? [1] : []

      content {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [local.organizations_id]
      }
    }
  }

  statement {
    sid    = "AllowAccountAccessToDynamoDBTable"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Scan",
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    resources = [
      format("arn:aws:dynamodb:%s:%s:table/%s", local.region, local.account_id, try(var.organizations.table.name, "organization-compliance"))
    ]
  }
}

## Provision a DynamoDB table to store organization metadata for AWS resources (if enabled)
resource "aws_dynamodb_table" "organizations" {
  count = local.enable_organizations ? 1 : 0

  name           = var.organizations.table.name
  billing_mode   = var.organizations.table.billing_mode
  hash_key       = "AccountId"
  read_capacity  = var.organizations.table.read_capacity
  tags           = var.tags
  write_capacity = var.organizations.table.write_capacity

  dynamic "server_side_encryption" {
    for_each = var.organizations.table.kms_key_id == null ? [] : [1]

    content {
      enabled     = true
      kms_key_arn = var.organizations.table.kms_key_id
    }
  }

  point_in_time_recovery {
    enabled = var.organizations.table.point_in_time_recovery_enabled
  }

  attribute {
    name = "AccountId"
    type = "S"
  }
}

## Update the DynamoDB table policy to allow access from the organization
resource "aws_dynamodb_resource_policy" "organizations_access" {
  count = local.enable_organizations ? 1 : 0

  resource_arn = aws_dynamodb_table.organizations[0].arn
  policy       = data.aws_iam_policy_document.organizations_access.json
}

## Provision the handler used to trigger the lambda function on organization 
## account movements and store the organization metadata in the DynamoDB table
module "organizations_handler" {
  count  = local.enable_organizations ? 1 : 0
  source = "./modules/organizations"

  dynamodb_table_arn = aws_dynamodb_table.organizations[0].arn
  lambda_description = var.organizations.lambda.description
  lambda_log_level   = var.organizations.lambda.log_level
  lambda_memory_size = var.organizations.lambda.memory_size
  lambda_name        = var.organizations.lambda.name
  lambda_runtime     = var.organizations.lambda.runtime
  lambda_timeout     = var.organizations.lambda.timeout
  tags               = var.tags

  depends_on = [
    aws_dynamodb_table.organizations,
  ]
}
