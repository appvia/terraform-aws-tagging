mock_provider "aws" {
  source = "./tests/mock"
}

variables {
  enable_organizations = true
  organizations_id     = "o-1234567890"
  policy               = <<-YAML
    version: 1
    rules:
      - name: required-tags
        steps:
          - assert: {tag: [Environment], present: true}
  YAML
  tags = {
    "CostCenter"  = "12345"
    "Environment" = "Production"
    "Owner"       = "Support"
    "Product"     = "Test"
    "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
  }
}

run "basic" {
  command = plan

  assert {
    condition     = aws_s3_bucket.policy.bucket == "tagging-compliance"
    error_message = "Policy bucket has incorrect name"
  }

  assert {
    condition     = aws_s3_bucket_versioning.policy.versioning_configuration[0].status == "Enabled"
    error_message = "Policy bucket versioning is not enabled"
  }

  assert {
    condition     = one([for r in aws_s3_bucket_server_side_encryption_configuration.policy.rule : one(r.apply_server_side_encryption_by_default).sse_algorithm]) == "AES256"
    error_message = "Policy bucket should use AES256 without a KMS key"
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.policy.block_public_acls,
      aws_s3_bucket_public_access_block.policy.block_public_policy,
      aws_s3_bucket_public_access_block.policy.ignore_public_acls,
      aws_s3_bucket_public_access_block.policy.restrict_public_buckets,
    ])
    error_message = "Policy bucket public access block must be fully enabled"
  }

  assert {
    condition = anytrue(flatten([
      for s in data.aws_iam_policy_document.bucket.statement : [
        for c in coalesce(s.condition, []) : c.variable == "aws:PrincipalOrgID" && contains(c.values, "o-1234567890")
      ]
    ]))
    error_message = "Bucket policy must grant access to the organization"
  }

  assert {
    condition = anytrue(flatten([
      for s in data.aws_iam_policy_document.bucket.statement : [
        for c in coalesce(s.condition, []) : s.effect == "Deny" && c.variable == "aws:SecureTransport" && contains(c.values, "false")
      ]
    ]))
    error_message = "Bucket policy must deny non-TLS access"
  }

  assert {
    condition     = aws_s3_object.policy.key == "policy.yaml"
    error_message = "Policy object has incorrect key"
  }

  assert {
    condition     = aws_s3_object.mappings.key == "mappings.yaml"
    error_message = "Mappings object has incorrect key"
  }

  assert {
    condition     = output.policy_version == sha256(var.policy)
    error_message = "policy_version must be the sha256 of the policy"
  }

  assert {
    condition     = output.accounts_key == null
    error_message = "accounts_key must be null without organizations"
  }
}

run "with_kms_key" {
  command = plan

  variables {
    bucket = {
      kms_key_arn = "arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555"
    }
  }

  assert {
    condition     = one([for r in aws_s3_bucket_server_side_encryption_configuration.policy.rule : one(r.apply_server_side_encryption_by_default).sse_algorithm]) == "aws:kms"
    error_message = "Policy bucket should use aws:kms with a KMS key"
  }
}

run "with_mappings" {
  command = plan

  variables {
    mappings = {
      aws_custom_thing = "AWS::Custom::Thing"
    }
  }

  assert {
    condition     = yamldecode(aws_s3_object.mappings.content).mappings["aws_custom_thing"] == "AWS::Custom::Thing"
    error_message = "Custom mappings must be merged into the shipped mappings"
  }

  assert {
    condition     = yamldecode(aws_s3_object.mappings.content).mappings["aws_s3_bucket"] == "AWS::S3::Bucket"
    error_message = "Shipped mappings must be retained"
  }
}

run "invalid_policy_version" {
  command = plan

  variables {
    policy = <<-YAML
      version: 2
      rules: []
    YAML
  }

  expect_failures = [var.policy]
}

run "invalid_mappings" {
  command = plan

  variables {
    mappings = {
      aws_s3_bucket = "s3bucket"
    }
  }

  expect_failures = [var.mappings]
}

run "with_organizations" {
  command = plan

  variables {
    organizations = {}
  }

  assert {
    condition     = output.accounts_key == "accounts.yaml"
    error_message = "accounts_key must be accounts.yaml when organizations is enabled"
  }
}

run "without_organizations_access" {
  command = plan

  variables {
    enable_organizations = false
    organizations_id     = null
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.bucket.statement : !(s.effect == "Allow" && anytrue([for p in s.principals : contains(p.identifiers, "*")]))
    ])
    error_message = "Bucket policy must not grant access to any principal without the organization condition"
  }
}

run "organizations_id_discovered" {
  command = plan

  variables {
    organizations_id = null
  }

  override_data {
    target = data.aws_organizations_organization.org[0]
    values = {
      id = "o-discovered"
    }
  }

  assert {
    condition     = output.organizations_id == "o-discovered"
    error_message = "The organization id must be discovered when not provided"
  }
}
