locals {
  ## Determine the Lambda function ARN to use in the conformance pack template
  lambda_arn = var.lambda_function_arn != null ? var.lambda_function_arn : try(module.lambda_function[0].lambda_arn, null)

  ## Indicates if the inventory version is looked up from the policy bucket (an inventory is
  ## configured and the version has not been pinned with var.inventory_version)
  inventory_lookup = var.accounts_key != null && var.policy_bucket_name != null && var.inventory_version == null

  ## The inventory version is the content-sha256 metadata of the inventory object, the
  ## same value the organizations lambda sets when it re-puts the pack, so plans do not
  ## drift and applies do not trigger an org-wide re-evaluation; "none" when absent.
  inventory_version = var.inventory_version != null ? var.inventory_version : try(data.aws_s3_object.inventory[0].metadata["content-sha256"], "none")

  ## The input parameters passed to the conformance pack; the version hashes force a
  ## re-evaluation when the policy, mappings or inventory change.
  pack_input_parameters = merge(var.input_parameters, {
    PolicyVersion    = var.policy_version
    MappingsVersion  = var.mappings_version
    InventoryVersion = local.inventory_version
  })

  ## The rendered conformance pack template
  template = templatefile("${path.module}/assets/conformance-pack.yaml.tmpl", {
    config_rule_name        = var.config_rule_name
    description             = var.pack_description
    lambda_function_arn     = local.lambda_arn
    max_execution_frequency = var.max_execution_frequency
    resource_types          = jsonencode(var.resource_types)
  })
}

## Create an S3 bucket to store the conformance pack template
resource "aws_s3_bucket" "conformance_pack" {
  bucket = var.s3_bucket_name
  tags   = var.tags
}

## Enable versioning for the conformance pack bucket
resource "aws_s3_bucket_versioning" "conformance_pack" {
  count  = var.s3_enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.conformance_pack.id

  versioning_configuration {
    status = "Enabled"
  }
}

## Block public access to the conformance pack bucket
resource "aws_s3_bucket_public_access_block" "conformance_pack" {
  bucket = aws_s3_bucket.conformance_pack.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

## Enable encryption for the conformance pack bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "conformance_pack" {
  bucket = aws_s3_bucket.conformance_pack.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.s3_kms_key_id == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.s3_kms_key_id
    }
  }
}

## Upload the conformance pack template to S3
resource "aws_s3_object" "conformance_pack_template" {
  bucket       = aws_s3_bucket.conformance_pack.id
  content_type = "application/x-yaml"
  key          = var.s3_template_key
  tags         = var.tags

  content = local.template
  etag    = md5(local.template)
}

## Provision the custom lambda function which can be shared across multiple
## config rules or conformance packs
module "lambda_function" {
  count  = var.lambda_function_arn == null ? 1 : 0
  source = "../validation"

  accounts_key                      = var.accounts_key
  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  kms_key_arn                       = var.kms_key_arn
  lambda_description                = format("Lambda function to evaluate tagging compliance for conformance pack %s", var.conformance_pack_name)
  lambda_name                       = "${var.config_rule_name}-compliance-tagging"
  lambda_role_name                  = "${var.config_rule_name}-compliance-tagging"
  mappings_key                      = var.mappings_key
  policy_bucket_arn                 = var.policy_bucket_arn
  policy_bucket_name                = var.policy_bucket_name
  policy_key                        = var.policy_key
  tags                              = var.tags
}

## Create the organization conformance pack
resource "aws_config_organization_conformance_pack" "tagging" {
  count = var.deploy_organization_wide ? 1 : 0

  name              = var.conformance_pack_name
  excluded_accounts = var.excluded_accounts
  template_s3_uri   = format("s3://%s/%s", aws_s3_bucket.conformance_pack.id, aws_s3_object.conformance_pack_template.key)

  dynamic "input_parameter" {
    for_each = local.pack_input_parameters

    content {
      parameter_name  = input_parameter.key
      parameter_value = input_parameter.value
    }
  }

  depends_on = [
    aws_s3_object.conformance_pack_template,
    module.lambda_function,
  ]
}

## Create an account-level conformance pack
resource "aws_config_conformance_pack" "tagging" {
  count = var.deploy_organization_wide ? 0 : 1

  name            = var.conformance_pack_name
  template_s3_uri = format("s3://%s/%s", aws_s3_bucket.conformance_pack.id, aws_s3_object.conformance_pack_template.key)

  dynamic "input_parameter" {
    for_each = local.pack_input_parameters

    content {
      parameter_name  = input_parameter.key
      parameter_value = input_parameter.value
    }
  }

  depends_on = [
    aws_s3_object.conformance_pack_template,
    module.lambda_function,
  ]
}
