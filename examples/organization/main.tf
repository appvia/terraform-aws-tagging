#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

data "aws_organizations_organization" "current" {}

locals {
  ## The organization id which is used in the policy
  organizations_id = data.aws_organizations_organization.current.id
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

  ## Enable the organizations inventory lambda
  ## NOTE: On first apply, comment out conformance_pack_name and conformance_pack_template_uri
  ## to avoid a circular dependency. After the pack module is created, uncomment these to enable
  ## automatic re-evaluation when the inventory changes.
  organizations = {
    # conformance_pack_name         = "tagging-compliance"
    # conformance_pack_template_uri = module.pack.s3_template_uri
    enable_account_event_sync = true
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

  ## S3 bucket for conformance pack template storage
  s3_bucket_name = "tagging-compliance-pack-templates"

  ## Conformance pack configuration
  conformance_pack_name    = "tagging-compliance"
  deploy_organization_wide = true
}
