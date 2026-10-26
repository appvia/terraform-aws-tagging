mock_provider "aws" {
  source = "./tests/mock"
}

## Build the lambda against the python shipped on the CI runners (python3.14 is not available)
variables {
  deploy_organization_wide = true
  lambda_runtime           = "python3.12"
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
      PolicyVersion    = "policy-hash"
      MappingsVersion  = "mappings-hash"
      InventoryVersion = "none"
    }
    error_message = "The pack must pass PolicyVersion, MappingsVersion and InventoryVersion=none without an inventory"
  }
}

run "organization_pack_with_inventory" {
  command = plan

  module {
    source = "./modules/pack"
  }

  variables {
    accounts_key = "accounts.yaml"
  }

  override_resource {
    target          = module.lambda_function[0].module.lambda_function.aws_lambda_function.this[0]
    override_during = plan
    values = {
      arn = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    }
  }

  override_data {
    target = data.aws_s3_objects.inventory[0]
    values = {
      keys = ["accounts.yaml", "accounts.yaml.bak"]
    }
  }

  override_data {
    target = data.aws_s3_object.inventory[0]
    values = {
      metadata = {
        "content-sha256" = "inventory-hash"
        "generated-at"   = "2026-10-19T00:00:00+00:00"
      }
    }
  }

  assert {
    condition = {
      for p in aws_config_organization_conformance_pack.tagging[0].input_parameter : p.parameter_name => p.parameter_value
    }["InventoryVersion"] == "inventory-hash"
    error_message = "InventoryVersion must be the content-sha256 metadata of the inventory object (as set by the organizations lambda)"
  }
}

run "organization_pack_inventory_absent" {
  command = plan

  module {
    source = "./modules/pack"
  }

  variables {
    accounts_key = "accounts.yaml"
  }

  override_resource {
    target          = module.lambda_function[0].module.lambda_function.aws_lambda_function.this[0]
    override_during = plan
    values = {
      arn = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    }
  }

  override_data {
    target = data.aws_s3_objects.inventory[0]
    values = {
      keys = ["accounts.yaml.bak"]
    }
  }

  assert {
    condition     = length(data.aws_s3_object.inventory) == 0
    error_message = "The inventory object must not be read when it does not exist"
  }

  assert {
    condition = {
      for p in aws_config_organization_conformance_pack.tagging[0].input_parameter : p.parameter_name => p.parameter_value
    }["InventoryVersion"] == "none"
    error_message = "InventoryVersion must be none when the inventory object does not exist yet"
  }
}

run "account_pack_with_inventory" {
  command = plan

  module {
    source = "./modules/pack"
  }

  variables {
    accounts_key             = "accounts.yaml"
    deploy_organization_wide = false
  }

  override_resource {
    target          = module.lambda_function[0].module.lambda_function.aws_lambda_function.this[0]
    override_during = plan
    values = {
      arn = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    }
  }

  override_data {
    target = data.aws_s3_objects.inventory[0]
    values = {
      keys = ["accounts.yaml"]
    }
  }

  override_data {
    target = data.aws_s3_object.inventory[0]
    values = {
      metadata = {
        "content-sha256" = "inventory-hash"
      }
    }
  }

  assert {
    condition = {
      for p in aws_config_conformance_pack.tagging[0].input_parameter : p.parameter_name => p.parameter_value
      } == {
      PolicyVersion    = "policy-hash"
      MappingsVersion  = "mappings-hash"
      InventoryVersion = "inventory-hash"
    }
    error_message = "The account-level pack must pass the inventory version too"
  }
}

## Bootstrap: the policy bucket is created in the same configuration, so the inventory
## version is pinned and the S3 data sources must not be read
run "organization_pack_inventory_version_pinned" {
  command = plan

  module {
    source = "./modules/pack"
  }

  variables {
    accounts_key      = "accounts.yaml"
    inventory_version = "none"
  }

  override_resource {
    target          = module.lambda_function[0].module.lambda_function.aws_lambda_function.this[0]
    override_during = plan
    values = {
      arn = "arn:aws:lambda:eu-west-2:123456789012:function:tagging-compliance-compliance-tagging"
    }
  }

  assert {
    condition     = length(data.aws_s3_objects.inventory) == 0 && length(data.aws_s3_object.inventory) == 0
    error_message = "No S3 data sources must be read when inventory_version is set"
  }

  assert {
    condition = {
      for p in aws_config_organization_conformance_pack.tagging[0].input_parameter : p.parameter_name => p.parameter_value
    }["InventoryVersion"] == "none"
    error_message = "InventoryVersion must be the pinned inventory_version"
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
