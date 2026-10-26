locals {
  ## The current account id
  account_id = data.aws_caller_identity.current.account_id
  ## The object keys the lambda reads from the policy bucket
  object_keys = compact([var.policy_key, var.mappings_key, var.accounts_key])
  ## The environment variables for the lambda function; ACCOUNTS_KEY is omitted when no inventory is configured
  environment_variables = merge(
    {
      LOG_LEVEL               = var.lambda_log_level
      MAPPINGS_KEY            = var.mappings_key
      POLICY_BUCKET           = var.policy_bucket_name
      POLICY_KEY              = var.policy_key
      RULES_CACHE_ENABLED     = var.rules_cache_enabled ? "true" : "false"
      RULES_CACHE_TTL_SECONDS = tostring(var.rules_cache_ttl_seconds)
    },
    var.accounts_key != null ? {
      ACCOUNTS_KEY = var.accounts_key
    } : {},
  )
}
