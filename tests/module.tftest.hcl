mock_provider "aws" {
  source = "./tests/mock"
}

run "basic" {
  command = plan

  variables {
    compliance = {
      table = {
        name = "tagging-compliance"
      }
    }
    enable_organizations = true
    organizations_id     = "o-1234567890"
    tags = {
      "CostCenter"  = "12345"
      "Environment" = "Production"
      "Owner"       = "Support"
      "Product"     = "Test"
      "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
    }
  }

  assert {
    # We should have a dynamodb table provisioned
    condition     = aws_dynamodb_table.compliance != null
    error_message = "DynamoDB table was not created"
  }

  assert {
    # The dynamodb table should have the correct name
    condition     = aws_dynamodb_table.compliance.name == "tagging-compliance"
    error_message = "DynamoDB table has incorrect name"
  }

  assert {
    # We should have a dynamodb resource policy provisioned
    condition     = aws_dynamodb_resource_policy.compliance != null
    error_message = "DynamoDB resource policy was not created"
  }
}

run "with_rules" {
  command = plan

  variables {
    compliance = {
      table = {
        name = "tagging-compliance"
      }
    }
    organizations_id = "o-1234567890"
    tags = {
      "CostCenter"  = "12345"
      "Environment" = "Production"
      "Owner"       = "Support"
      "Product"     = "Test"
      "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
    }
    rules = [
      {
        RuleId       = "ec2-tagging-rule"
        Enabled      = true
        Required     = true
        ResourceType = "AWS::EC2::*"
        Tag          = "Environment"
        Values       = ["Development"]
        AccountIds   = ["*"]
      }
    ]
  }
}