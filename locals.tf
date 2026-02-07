locals {
  ## The current account id which is used in the policy 
  account_id = data.aws_caller_identity.current.account_id
  ## The organization id which is used in the policy 
  organization_id = var.organization_id != null ? var.organization_id : try(data.aws_organizations_organization.org[0].id, null)
}