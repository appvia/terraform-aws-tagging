## List the account inventory key so a missing inventory (e.g. before the organizations
## lambda first runs) does not fail the plan. Skipped when inventory_version is pinned.
data "aws_s3_objects" "inventory" {
  count = local.inventory_lookup ? 1 : 0

  bucket = var.policy_bucket_name
  prefix = var.accounts_key
}

## Read the inventory object's metadata; content-sha256 is written by the organizations
## lambda and is the same value it uses when re-putting the pack, so both agree
data "aws_s3_object" "inventory" {
  count = local.inventory_lookup && contains(try(data.aws_s3_objects.inventory[0].keys, []), var.accounts_key) ? 1 : 0

  bucket = var.policy_bucket_name
  key    = var.accounts_key
}
