mock_provider "aws" {
  source = "./tests/mock"
}

run "basic" {
  command = plan

  module {
    source = "./modules/config"
  }

  ## Build the lambda against the python shipped on the CI runners (python3.14 is not available)
  variables {
    config_name           = "tagging-compliance"
    config_resource_types = ["AWS::EC2::Instance"]
    lambda_name           = "tagging-compliance-evaluator"
    lambda_runtime        = "python3.12"
    mappings_version      = "mappings-hash"
    policy_bucket_arn     = "arn:aws:s3:::tagging-compliance"
    policy_bucket_name    = "tagging-compliance"
    policy_version        = "policy-hash"
  }

  assert {
    condition     = aws_config_config_rule.tagging_compliance.name == "tagging-compliance"
    error_message = "Config rule has incorrect name"
  }

  assert {
    condition = jsondecode(aws_config_config_rule.tagging_compliance.input_parameters) == {
      PolicyVersion   = "policy-hash"
      MappingsVersion = "mappings-hash"
    }
    error_message = "Config rule input parameters must carry only the policy and mappings versions"
  }
}
