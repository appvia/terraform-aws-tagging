## Provision the handler used to trigger the lambda function on organization
## account movements and store the account inventory in the policy bucket
module "organizations_handler" {
  count  = local.enable_organizations ? 1 : 0
  source = "./modules/organizations"

  accounts_key                  = local.accounts_key
  bucket_arn                    = aws_s3_bucket.policy.arn
  bucket_name                   = aws_s3_bucket.policy.id
  conformance_pack_name         = var.organizations.conformance_pack_name
  conformance_pack_template_uri = var.organizations.conformance_pack_template_uri
  enable_account_event_sync     = var.organizations.enable_account_event_sync
  kms_key_arn                   = var.bucket.kms_key_arn
  lambda_description            = var.organizations.lambda.description
  lambda_log_level              = var.organizations.lambda.log_level
  lambda_memory_size            = var.organizations.lambda.memory_size
  lambda_name                   = var.organizations.lambda.name
  lambda_runtime                = var.organizations.lambda.runtime
  lambda_timeout                = var.organizations.lambda.timeout
  tags                          = var.tags
}
