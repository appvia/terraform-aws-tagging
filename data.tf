## Find the organization id if not provided as a variable
data "aws_organizations_organization" "org" {
  ## Only query for the organization if an organization id is not provided as a variable
  count = var.organizations_id == null && var.enable_organizations ? 1 : 0
}

## Find the current account id
data "aws_caller_identity" "current" {}

## Find the current region
data "aws_region" "current" {}