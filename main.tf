## Provision a Dynamodb table to store tags for AWS resources
resource "aws_dynamodb_table" "compliance" {
  name           = var.compliance.table.name
  billing_mode   = var.compliance.table.billing_mode
  hash_key       = "RuleId"
  read_capacity  = var.compliance.table.read_capacity
  tags           = var.tags
  write_capacity = var.compliance.table.write_capacity

  dynamic "server_side_encryption" {
    for_each = var.compliance.table.kms_key_id == null ? [] : [1]

    content {
      enabled     = true
      kms_key_arn = var.compliance.table.kms_key_id
    }
  }

  point_in_time_recovery {
    enabled = var.compliance.table.point_in_time_recovery_enabled
  }

  attribute {
    name = "RuleId"
    type = "S"
  }
}

## Update the DynamoDB policy permitting access to the table from the organization
data "aws_iam_policy_document" "dynamodb_access" {
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
      aws_dynamodb_table.compliance.arn,
    ]

    dynamic "condition" {
      for_each = var.enable_organizations ? [1] : []

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
      aws_dynamodb_table.compliance.arn,
    ]
  }
}

## Update the DynamoDB table policy to allow access from the organization
resource "aws_dynamodb_resource_policy" "compliance" {
  resource_arn = aws_dynamodb_table.compliance.arn
  policy       = data.aws_iam_policy_document.dynamodb_access.json
}

## Provision any compliance rules in the dynamodb table
module "compliance_rules" {
  count  = length(var.rules) > 0 ? 1 : 0
  source = "./modules/compliance"

  dynamodb_table_name = aws_dynamodb_table.compliance.name
  rules               = var.rules

  depends_on = [
    aws_dynamodb_table.compliance,
    aws_dynamodb_resource_policy.compliance,
  ]
}