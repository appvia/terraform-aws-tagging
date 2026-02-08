locals {
  ## The current account id which is used in the policy 
  account_id = data.aws_caller_identity.current.account_id
  ## The current region which is used in the policy
  region = data.aws_region.current.region
  ## The organization id which is used in the policy 
  organizations_id = var.enable_organizations ? var.organizations_id : try(data.aws_organizations_organization.org[0].id, null)
}