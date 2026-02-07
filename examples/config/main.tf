#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

module "config" {
  source = "../../modules/config"

  ## The name of the DynamoDB table to store tags for AWS resources. 
  dynamodb_table_arn = "arn:aws:dynamodb:eu-west-1:123456789012:table/tagging-compliance"
  ## The name of the AWS Config rule to create
  config_name = "tagging-compliance"
  ## The resource types to evaluate for compliance  
  config_resource_types = ["AWS::S3::Bucket"]
}