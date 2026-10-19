#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

## Provision the S3 bucket with the tagging policy
module "tagging" {
  source = "../../"

  ## The tagging policy as YAML content
  policy = file("${path.module}/tagging-policy.yaml")

  ## S3 bucket configuration
  bucket = {
    name = "tagging-compliance-config"
  }
}

## Provision the AWS Config rule to evaluate compliance
module "config" {
  source = "../../modules/config"

  ## Policy bucket outputs
  policy_bucket_name = module.tagging.bucket_name
  policy_bucket_arn  = module.tagging.bucket_arn
  policy_key         = module.tagging.policy_key
  policy_version     = module.tagging.policy_version
  mappings_key       = module.tagging.mappings_key
  mappings_version   = module.tagging.mappings_version
  accounts_key       = module.tagging.accounts_key
  kms_key_arn        = module.tagging.kms_key_arn

  ## The name of the AWS Config rule to create
  config_name = "tagging-compliance-test"
  ## The resource types to evaluate for compliance
  config_resource_types = ["AWS::IAM::Role"]
  ## Name of the lambda
  lambda_name = "tagging-compliance-test"
  ## The logging level for the Lambda function (e.g., "DEBUG", "INFO", "ERROR")
  lambda_log_level = "DEBUG"
}
