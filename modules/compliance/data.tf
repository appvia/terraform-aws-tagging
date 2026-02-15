
## Find the dynamodb table
data "aws_dynamodb_table" "table" {
  name = var.compliance_rule_table_name
}
