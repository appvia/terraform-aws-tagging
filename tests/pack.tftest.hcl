mock_provider "aws" {
  source = "./tests/mock"
}

variables {
  deploy_organization_wide = true
  mappings_version         = "mappings-hash"
  policy_bucket_arn        = "arn:aws:s3:::tagging-compliance"
  policy_bucket_name       = "tagging-compliance"
  policy_version           = "policy-hash"
  s3_bucket_name           = "tagging-conformance-pack"
}

run "organization_pack" {
  command = plan

  module {
    source = "./modules/pack"
  }

  ## The lambda ARN is computed; pin it at plan time so the rendered template is known
  override_resource {
    target          = module.lambda_function[0].module.lambda_function.aws_lambda_function.this[0]
    override_during = plan
    values = {
      arn = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    }
  }

  assert {
    condition = toset(keys(yamldecode(aws_s3_object.conformance_pack_template.content).Parameters)) == toset([
      "InventoryVersion",
      "MappingsVersion",
      "PolicyVersion",
    ])
    error_message = "The template must declare the PolicyVersion, MappingsVersion and InventoryVersion parameters"
  }

  assert {
    condition = alltrue([
      for p in values(yamldecode(aws_s3_object.conformance_pack_template.content).Parameters) : p.Type == "String" && p.Default == "none"
    ])
    error_message = "The version parameters must be strings defaulting to none"
  }

  assert {
    condition = yamldecode(aws_s3_object.conformance_pack_template.content).Resources.TaggingComplianceRule.Properties.InputParameters == {
      PolicyVersion    = { Ref = "PolicyVersion" }
      MappingsVersion  = { Ref = "MappingsVersion" }
      InventoryVersion = { Ref = "InventoryVersion" }
    }
    error_message = "The rule input parameters must reference the version parameters"
  }

  assert {
    condition     = yamldecode(aws_s3_object.conformance_pack_template.content).Resources.TaggingComplianceRule.Properties.Source.SourceIdentifier == "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    error_message = "The template must reference the module's own lambda when lambda_function_arn is unset"
  }

  assert {
    condition = {
      for p in aws_config_organization_conformance_pack.tagging[0].input_parameter : p.parameter_name => p.parameter_value
      } == {
      PolicyVersion   = "policy-hash"
      MappingsVersion = "mappings-hash"
    }
    error_message = "The pack must pass PolicyVersion and MappingsVersion only (InventoryVersion is left to the template default)"
  }
}

run "external_lambda" {
  command = plan

  module {
    source = "./modules/pack"
  }

  variables {
    lambda_function_arn = "arn:aws:lambda:eu-west-2:123456789012:function:external"
    policy_bucket_arn   = null
    policy_bucket_name  = null
  }

  assert {
    condition     = yamldecode(aws_s3_object.conformance_pack_template.content).Resources.TaggingComplianceRule.Properties.Source.SourceIdentifier == "arn:aws:lambda:eu-west-2:123456789012:function:external"
    error_message = "The template must reference the provided lambda_function_arn"
  }
}
