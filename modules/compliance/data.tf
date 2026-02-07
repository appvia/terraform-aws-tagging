
## Find the dynamodb table 
data "aws_dynamodb_table" "table" {
  name = var.dynamodb_table_name
}
