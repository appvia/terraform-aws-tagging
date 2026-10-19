#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

data "aws_organizations_organization" "current" {}

locals {
  ## The organization id which is used in the policy
  organizations_id = data.aws_organizations_organization.current.id
  ## The name of the organization conformance pack
  conformance_pack_name = "tagging-compliance"
  ## The bucket and key of the conformance pack template, shared with the pack module
  pack_bucket_name  = "tagging-compliance-pack-templates"
  pack_template_key = "conformance-packs/tagging-compliance.yaml"
}

## Provision the S3 bucket with the tagging policy and organizations support
module "tagging" {
  source = "../../"

  ## The tagging policy as YAML content
  policy = file("${path.module}/tagging-policy.yaml")

  ## S3 bucket configuration
  bucket = {
    name = "tagging-compliance-org"
  }

  ## Enable organization-wide access
  enable_organizations = true
  organizations_id     = local.organizations_id

  ## Enable the organizations inventory lambda, re-putting the conformance pack when the
  ## inventory changes. The template URI is built from the same locals passed to the pack
  ## module: referencing module.pack.s3_template_uri here would create a dependency cycle,
  ## as the pack module consumes this module's accounts_key output.
  organizations = {
    conformance_pack_name         = local.conformance_pack_name
    conformance_pack_template_uri = format("s3://%s/%s", local.pack_bucket_name, local.pack_template_key)
    enable_account_event_sync     = true
    lambda = {
      name        = "organization-compliance"
      description = "Manages account inventory for tagging compliance"
      log_level   = "INFO"
    }
  }
}

## Deploy organization-wide conformance pack
module "pack" {
  source = "../../modules/pack"

  ## Policy bucket outputs
  policy_bucket_name = module.tagging.bucket_name
  policy_bucket_arn  = module.tagging.bucket_arn
  policy_key         = module.tagging.policy_key
  policy_version     = module.tagging.policy_version
  mappings_key       = module.tagging.mappings_key
  mappings_version   = module.tagging.mappings_version
  accounts_key       = module.tagging.accounts_key
  kms_key_arn        = module.tagging.kms_key_arn

  ## Bootstrap: pass "none" on the first apply when the bucket is created
  ## in the same configuration (the bucket does not exist at plan time).
  ## After the first apply succeeds, remove this line so the version follows
  ## the inventory written by the organizations lambda.
  inventory_version = "none"

  ## S3 bucket and key for conformance pack template storage
  s3_bucket_name  = local.pack_bucket_name
  s3_template_key = local.pack_template_key

  ## Conformance pack configuration
  conformance_pack_name    = local.conformance_pack_name
  deploy_organization_wide = true
}
