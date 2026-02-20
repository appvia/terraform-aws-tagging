mock_provider "aws" {
  source = "./tests/mock"
}

override_module {
  target = module.lambda_function
  outputs = {
    lambda_arn  = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance"
    lambda_name = "tagging-compliance"
  }
}

run "config_frequency_enabled" {
  command = plan

  module {
    source = "./modules/config"
  }

  variables {
    config_frequency          = "One_Hour"
    config_resource_types     = ["AWS::EC2::*"]
    compliance_rule_table_arn = "arn:aws:dynamodb:eu-west-2:123456789012:table/tagging-compliance"
    tags = {
      "CostCenter"  = "12345"
      "Environment" = "Production"
      "Owner"       = "Support"
      "Product"     = "Test"
      "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
    }
  }

  assert {
    condition = length([
      for source_detail in aws_config_config_rule.tagging_compliance.source[0].source_detail : source_detail
      if source_detail.message_type == "ScheduledNotification"
    ]) == 1
    error_message = "ScheduledNotification source detail should be added when config_frequency is set."
  }

  assert {
    condition = one([
      for source_detail in aws_config_config_rule.tagging_compliance.source[0].source_detail : source_detail.maximum_execution_frequency
      if source_detail.message_type == "ScheduledNotification"
    ]) == "One_Hour"
    error_message = "ScheduledNotification source detail should set maximum_execution_frequency to the configured value."
  }
}

run "config_frequency_invalid" {
  command = plan

  module {
    source = "./modules/config"
  }

  variables {
    config_frequency          = "Ten_Minutes"
    config_resource_types     = ["AWS::EC2::*"]
    compliance_rule_table_arn = "arn:aws:dynamodb:eu-west-2:123456789012:table/tagging-compliance"
    tags = {
      "CostCenter"  = "12345"
      "Environment" = "Production"
      "Owner"       = "Support"
      "Product"     = "Test"
      "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
    }
  }

  expect_failures = [
    var.config_frequency
  ]
}
