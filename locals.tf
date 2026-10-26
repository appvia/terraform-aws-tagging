locals {
  ## The current account id which is used in the policy
  account_id = data.aws_caller_identity.current.account_id
  ## The organization id which is used in the policy
  organizations_id = var.organizations_id != null ? var.organizations_id : try(data.aws_organizations_organization.org[0].id, null)
  ## Indicates if the organizations inventory handler is enabled
  enable_organizations = var.organizations != null
  ## The object key of the tagging policy in the bucket
  policy_key = "policy.yaml"
  ## The object key of the resource type mappings in the bucket
  mappings_key = "mappings.yaml"
  ## The object key of the account inventory in the bucket (only when organizations is enabled)
  accounts_key = local.enable_organizations ? "accounts.yaml" : null
  ## The rendered mappings, the shipped defaults merged with any consumer overrides
  mappings = yamlencode({
    version  = 1
    mappings = merge(yamldecode(file("${path.module}/modules/validation/assets/mappings.yaml")).mappings, var.mappings)
  })
}
