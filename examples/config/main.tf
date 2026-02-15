#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

module "config" {
  source = "../../modules/config"

  ## The name of the DynamoDB table to store tags for AWS resources.
  compliance_rule_table_arn = var.compliance_rule_table_arn
  ## The name of the organization to allow access to the DynamoDB table
  organizations_table_arn = var.organizations_table_arn
  ## The name of the AWS Config rule to create
  config_name = "tagging-compliance"
  ## The resource types to evaluate for compliance
  config_resource_types = ["AWS::S3::Bucket"]
  ## The logging level for the Lambda function (e.g., "DEBUG", "INFO", "ERROR")
  lambda_log_level = "DEBUG"
}

