## Provision the schedules in the dynamodb table 
resource "aws_dynamodb_table_item" "tagging" {
  for_each = {
    for rule in var.rules : rule.RuleId => rule
  }

  hash_key   = data.aws_dynamodb_table.table.hash_key
  range_key  = data.aws_dynamodb_table.table.range_key
  table_name = data.aws_dynamodb_table.table.name

  item = jsonencode({
    RuleId = {
      S = each.value.RuleId
    }
    ResourceType = {
      S = each.value.ResourceType
    }
    Tag = {
      S = each.value.Tag
    }
    Enabled = {
      BOOL = each.value.Enabled
    }
    Required = {
      BOOL = each.value.Required
    }
    ValuePattern = {
      S = each.value.ValuePattern != null ? each.value.ValuePattern : ""
    }
    Values = {
      S = jsonencode(each.value.Values)
    }
    AccountIds = {
      S = jsonencode(each.value.AccountIds)
    }
  })
}