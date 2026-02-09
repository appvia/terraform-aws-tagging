#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

data "aws_organizations_organization" "current" {}

locals {
  ## The organization id which is used in the policy
  organizations_id = data.aws_organizations_organization.current.id
}

## Provision the compliance rules in the DynamoDB table
module "compliance" {
  source = "../../"

  enable_organizations = true
  organizations_id     = local.organizations_id

  # Configuration for the DynamoDB table to store compliance rules.
  compliance = {
    table = {
      name = "tagging-compliance"
    }
  }

  organizations = {
    table = {
      name = "organizational-accounts"
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
      #AccountIds   = ["*"]
      OrganizationalPaths = ["root/Sandbox"]
    }
  ]
}