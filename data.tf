## Find the organization id if not provided as a variable
data "aws_organizations_organization" "org" {
  ## Only query for the organization if an organization id is not provided as a variable
  count = var.organization_id == null ? 1 : 0
}