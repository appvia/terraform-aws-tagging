#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

module "compliance" {
  source = "../../modules/compliance"

  ## The name of the DynamoDB table to store tags for AWS resources. 
  dynamodb_table_name = "tagging-compliance"
  ## List of compliance rules to be stored in the DynamoDB table.
  rules = [
    {
      RuleId       = "ec2-environment-tag-compliance",
      ResourceType = "AWS::EC2::*"
      Tag : "Environment",
      Enabled : true,
      Required : true,
      Values : ["Production", "Staging", "Development"],
      AccountIds : ["*"]
    },
    {
      RuleId = "s3-data-classification-tag-compliance",
      ResourceType : "AWS::S3::*",
      Tag : "DataClassification",
      Enabled : true,
      Required : true,
      Values : ["Public", "Private", "Confidential"],
      AccountIds : ["*"]
    }
  ]
}