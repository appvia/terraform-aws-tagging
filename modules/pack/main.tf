locals {
  ## Determine the Lambda function ARN to use in the conformance pack template
  lambda_arn = var.lambda_function_arn != null ? var.lambda_function_arn : try(module.lambda_function.lambda_arn, null)
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

## Enable default encryption for the conformance pack bucket
resource "aws_s3_bucket_default_encryption" "conformance_pack" {
  count = var.s3_kms_key_id == null ? 1 : 0

  bucket = aws_s3_bucket.conformance_pack.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

## Enable encryption for the conformance pack bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "conformance_pack" {
  count  = var.s3_kms_key_id != null ? 1 : 0
  bucket = aws_s3_bucket.conformance_pack.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
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

  content = templatefile("${path.module}/assets/conformance-pack.yaml.tmpl", {
    config_rule_name        = var.config_rule_name
    description             = var.pack_description
    dynamodb_table_arn      = var.dynamodb_table_arn
    lambda_function_arn     = local.lambda_arn
    max_execution_frequency = var.max_execution_frequency
    resource_types          = jsonencode(var.resource_types)
  })

  etag = md5(templatefile("${path.module}/assets/conformance-pack.yaml.tmpl", {
    config_rule_name        = var.config_rule_name
    description             = var.pack_description
    dynamodb_table_arn      = var.dynamodb_table_arn
    lambda_function_arn     = local.lambda_arn
    max_execution_frequency = var.max_execution_frequency
    resource_types          = jsonencode(var.resource_types)
  }))
}

## Provision the custom lambda function which can be shared across multiple 
## config rules or conformance packs
module "lambda_function" {
  count  = var.lambda_function_arn == null ? 1 : 0
  source = "../validation"

  cloudwatch_logs_kms_key_id        = var.cloudwatch_logs_kms_key_id
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  dynamodb_table_arn                = var.dynamodb_table_arn
  lambda_description                = format("Lambda function to evaluate tagging compliance for conformance pack %s", var.conformance_pack_name)
  lambda_name                       = "${var.config_rule_name}-compliance-tagging"
  lambda_role_name                  = "${var.config_rule_name}-compliance-tagging"
  tags                              = var.tags
}

## Create the organization conformance pack
resource "aws_config_organization_conformance_pack" "tagging" {
  count = var.deploy_organization_wide ? 1 : 0

  name              = var.conformance_pack_name
  excluded_accounts = var.excluded_accounts
  template_s3_uri   = format("s3://%s/%s", aws_s3_bucket.conformance_pack.id, aws_s3_object.conformance_pack_template.key)

  dynamic "input_parameter" {
    for_each = var.input_parameters

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
    for_each = var.input_parameters

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
