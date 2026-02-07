## Find the organization id if not provided as a variable
data "aws_organizations_organization" "org" {
  ## Only query for the organization if an organization id is not provided as a variable
  count = var.organization_id == null && var.enable_organization_access ? 1 : 0
}

## Find the current account id
data "aws_caller_identity" "current" {}