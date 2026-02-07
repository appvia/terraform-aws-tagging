locals {
  ## The list of compliance fields to be stored in the DynamoDB table.
  compliance_fields = {
    "AccountIds"   = "S"
    "Enabled"      = "B"
    "Required"     = "B"
    "ResourceType" = "S"
    "RuleId"       = "S"
    "Tag"          = "S"
    "ValuePattern" = "S"
    "Values"       = "S"
  }

  ## The organization id which is used in the policy 
  organization_id = var.organization_id != null ? var.organization_id : try(data.aws_organizations_organization.org[0].id, null)
}