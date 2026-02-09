mock_provider "aws" {
  source = "./tests/mock"
}

run "basic" {
  command = plan

  module {
    source = "./modules/compliance"
  }

  variables {
    dynamodb_table_name = "tagging-compliance"
    rules = [
      {
        RuleId        = "ec2-tagging-rule"
        Enabled       = true
        Required      = true
        ResourceTypes = ["AWS::EC2::*"]
        Tag           = "Environment"
        ValuePattern  = ""
        Values        = ["Development"]
        AccountIds    = ["*"]
      }
    ]
  }

  assert {
    # We should have a dynamodb table item provisioned for the rule
    condition     = aws_dynamodb_table_item.tagging["ec2-tagging-rule"] != null
    error_message = "DynamoDB table item for the rule was not created"
  }
}
