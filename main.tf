## Provision a Dynamodb table to store tags for AWS resources
resource "aws_dynamodb_table" "compliance" {
  name         = var.dynamodb_table_name
  billing_mode = var.dynamodb_billing_mode
  hash_key     = "ResourceType"
  tags         = var.tags

  dynamic "server_side_encryption" {
    for_each = var.dynamodb_table_kms_key_id == null ? [] : [1]

    content {
      enabled     = true
      kms_key_arn = var.dynamodb_table_kms_key_id
    }
  }

  point_in_time_recovery {
    enabled = var.dynamodb_table_point_in_time_recovery_enabled
  }

  ## Define all the fields for the dynamodb table
  dynamic "attribute" {
    for_each = local.compliance_fields
    content {
      name = attribute.key
      type = attribute.value
    }
  }
}

## Update the DynamoDB policy permitting access to the table from the organization
data "aws_iam_policy_document" "dynamodb_access" {
  statement {
    sid    = "AllowOrganizationAccessToDynamoDBTable"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:GetItems",
      "dynamodb:Scan",
    ]
    resources = [
      aws_dynamodb_table.compliance.arn,
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [local.organization_id]
    }
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
}