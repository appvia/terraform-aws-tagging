# NOTE: This test requires actual AWS credentials or a fully functional mock provider
# The terraform-aws-modules/lambda/aws module contains nested data sources that
# cannot be properly mocked with Terraform's current testing framework.
# 
# To run this test, ensure you have AWS credentials configured.

# mock_provider "aws" {}

# run "basic" {
#   command = plan
#   
#   module {
#     source = "./modules/config"
#   }

#   variables {
#     dynamodb_table_arn = "arn:aws:dynamodb:eu-west-1:123456789012:table/tagging-compliance"
#     config_resource_types = ["AWS::EC2::*"]
#     lambda_name = "tagging-compliance-evaluator"
#     config_name = "tagging-compliance"
#   }

#   assert {
#     # We should have an AWS Config rule provisioned
#     condition = aws_config_config_rule.tagging != null
#     error_message = "AWS Config rule was not created"
#   }

#   assert {
#     # Config rule should have correct name
#     condition = aws_config_config_rule.tagging.name == "tagging-compliance"
#     error_message = "Config rule has incorrect name"
#   }
# }
