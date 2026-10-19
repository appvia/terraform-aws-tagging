locals {
  ## The current account id
  account_id = data.aws_caller_identity.current.account_id
  ## The object keys the lambda reads from the policy bucket
  object_keys = compact([var.policy_key, var.mappings_key, var.accounts_key])
}
