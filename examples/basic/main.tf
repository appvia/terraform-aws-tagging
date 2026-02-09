#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

## Provision the compliance rules in the DynamoDB table
module "compliance" {
  source = "../../"

  # Configuration for the DynamoDB table to store compliance rules.
  compliance = {
    table = {
      name = "tagging-compliance"
    }
  }

  ## Collection of compliance rules to be stored in the DynamoDB table.
  rules = [
    {
      RuleId        = "ec2-tagging-rule"
      ResourceTypes = ["AWS::EC2::*"]
      Tag           = "Environment"
      Values        = ["Development"]
      AccountIds    = ["*"]
    },
    {
      RuleId        = "s3-tagging-rule"
      ResourceTypes = ["AWS::S3::*"]
      Tag           = "Environment"
      AccountIds    = ["*"]
    }
  ]
}

## Provision the AWS Config rule to evaluate compliance of AWS 
## resources with the rules stored in the DynamoDB table
module "config" {
  source = "../../modules/config"

  ## The name of the DynamoDB table to store tags for AWS resources. 
  dynamodb_table_arn = module.compliance.dynamodb_table_arn
  ## The name of the AWS Config rule to create
  config_name = "tagging-compliance"
  ## The resource types to evaluate for compliance
  config_resource_types = ["AWS::S3::Bucket"]

  depends_on = [
    module.compliance,
  ]
}