mock_provider "aws" {
  source = "./tests/mock"
}

variables {
  policy_bucket_arn  = "arn:aws:s3:::tagging-compliance"
  policy_bucket_name = "tagging-compliance"
}

run "without_inventory_or_kms" {
  command = plan

  module {
    source = "./modules/validation"
  }

  assert {
    condition = toset(one([for s in data.aws_iam_policy_document.permissions.statement : s.resources if s.sid == "AllowPolicyRead"])) == toset([
      "arn:aws:s3:::tagging-compliance/policy.yaml",
      "arn:aws:s3:::tagging-compliance/mappings.yaml",
    ])
    error_message = "s3:GetObject must be granted on exactly the policy and mappings objects"
  }

  assert {
    condition     = one([for s in data.aws_iam_policy_document.permissions.statement : s.actions if s.sid == "AllowPolicyRead"]) == toset(["s3:GetObject"])
    error_message = "The policy read statement must only grant s3:GetObject"
  }

  assert {
    condition     = !anytrue([for s in data.aws_iam_policy_document.permissions.statement : contains(tolist(s.actions), "kms:Decrypt")])
    error_message = "kms:Decrypt must not be granted without a KMS key"
  }

  assert {
    condition     = !contains(keys(output.environment_variables), "ACCOUNTS_KEY")
    error_message = "ACCOUNTS_KEY must be absent when accounts_key is null"
  }

  assert {
    condition     = output.environment_variables["POLICY_BUCKET"] == "tagging-compliance" && output.environment_variables["POLICY_KEY"] == "policy.yaml" && output.environment_variables["MAPPINGS_KEY"] == "mappings.yaml"
    error_message = "The policy location environment variables are incorrect"
  }
}

run "with_inventory_and_kms" {
  command = plan

  module {
    source = "./modules/validation"
  }

  variables {
    accounts_key = "accounts.yaml"
    kms_key_arn  = "arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition = toset(one([for s in data.aws_iam_policy_document.permissions.statement : s.resources if s.sid == "AllowPolicyRead"])) == toset([
      "arn:aws:s3:::tagging-compliance/policy.yaml",
      "arn:aws:s3:::tagging-compliance/mappings.yaml",
      "arn:aws:s3:::tagging-compliance/accounts.yaml",
    ])
    error_message = "s3:GetObject must be granted on exactly the policy, mappings and accounts objects"
  }

  assert {
    condition = one([for s in data.aws_iam_policy_document.permissions.statement : s.resources if contains(tolist(s.actions), "kms:Decrypt")]) == toset([
      "arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555",
    ])
    error_message = "kms:Decrypt must be granted on the KMS key when set"
  }

  assert {
    condition     = output.environment_variables["ACCOUNTS_KEY"] == "accounts.yaml"
    error_message = "ACCOUNTS_KEY must be set when accounts_key is set"
  }
}

run "missing_policy_bucket" {
  command = plan

  module {
    source = "./modules/validation"
  }

  variables {
    policy_bucket_arn  = null
    policy_bucket_name = null
  }

  expect_failures = [
    var.policy_bucket_arn,
    var.policy_bucket_name,
  ]
}
