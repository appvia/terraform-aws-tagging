output "entities" {
  description = "The list of entities for the tagging compliance rules stored in the DynamoDB table."
  value       = var.rules
}

output "rules" {
  description = "List of all the rendered DynamoDB item rules."
  value       = [for item in aws_dynamodb_table_item.tagging : item.item]
}