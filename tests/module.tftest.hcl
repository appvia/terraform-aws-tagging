mock_provider "aws" {
  source = "./tests/mock"
}

variables {
  enable_organizations = true
  organizations_id     = "o-1234567890"
  ## A multi-rule policy whose rules differ in shape (with/without description, nested rules)
  policy = <<-YAML
    version: 1
    exclude_resource_types: []
    rules:
      - name: required-tags
        description: Every taggable resource carries the baseline tags
        steps:
          - assert: {tag: [Environment, Product, GitRepo], present: true}
      - name: git-repo-tag
        steps:
          - filter: {tag: GitRepo, present: true}
          - assert: {tag: GitRepo, starts_with: https://github.com/}
      - name: environment-values
        description: Environment is one of the allowed values
        steps:
          - filter: {tag: Environment, present: true}
          - assert: {tag: Environment, in: [Production, Staging, Development]}
      - name: grouped
        rules:
          - name: data-classification
            steps:
              - filter: {type: [aws_s3_bucket, AWS::RDS::DBInstance]}
              - assert: {tag: DataClassification, present: true}
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

run "empty_rules" {
  command = plan

  variables {
    policy = <<-YAML
      version: 1
      rules: []
    YAML
  }

  assert {
    condition     = output.policy_version == sha256(var.policy)
    error_message = "An empty rules list must be accepted"
  }
}

run "invalid_policy_rules_map" {
  command = plan

  variables {
    policy = <<-YAML
      version: 1
      rules: {a: 1}
    YAML
  }

  expect_failures = [var.policy]
}

run "invalid_policy_rules_string" {
  command = plan

  variables {
    policy = <<-YAML
      version: 1
      rules: none
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

run "organizations_with_conformance_pack" {
  command = plan

  variables {
    organizations = {
      conformance_pack_name         = "tagging-compliance"
      conformance_pack_template_uri = "s3://tagging-conformance-pack/conformance-packs/tagging-compliance.yaml"
    }
  }

  assert {
    condition     = output.accounts_key == "accounts.yaml"
    error_message = "accounts_key must be accounts.yaml when organizations is enabled"
  }
}

run "organizations_module_events_and_permissions" {
  command = plan

  module {
    source = "./modules/organizations"
  }

  variables {
    bucket_arn                    = "arn:aws:s3:::tagging-compliance"
    bucket_name                   = "tagging-compliance"
    conformance_pack_name         = "tagging-compliance"
    conformance_pack_template_uri = "s3://tagging-conformance-pack/conformance-packs/tagging-compliance.yaml"
    enable_account_event_sync     = true
  }

  assert {
    condition = jsondecode(aws_cloudwatch_event_rule.account_events[0].event_pattern).detail.eventName == [
      "CreateAccount", "CloseAccount", "MoveAccount", "TagResource", "UntagResource",
    ]
    error_message = "The account event rule must match create, close, move, tag and untag events"
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.scheduled_sync) == 1
    error_message = "The scheduled sync must be enabled by default"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.permissions.statement : s.effect == "Allow" && contains(s.actions, "s3:PutObject") && contains(s.actions, "s3:GetObject") && toset(s.resources) == toset(["arn:aws:s3:::tagging-compliance/accounts.yaml"])
    ])
    error_message = "The lambda must be able to read and write the accounts object only"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.permissions.statement : contains(s.actions, "organizations:ListTagsForResource")
    ])
    error_message = "The lambda must be granted organizations:ListTagsForResource explicitly"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.permissions.statement : !anytrue([for a in s.actions : startswith(a, "dynamodb:")])
    ])
    error_message = "The lambda must not be granted any DynamoDB permissions"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.permissions.statement : toset(s.actions) == toset([
        "config:DescribeOrganizationConformancePacks",
        "config:PutOrganizationConformancePack",
        "organizations:DescribeOrganization",
        "organizations:EnableAWSServiceAccess",
        "organizations:ListAccounts",
        "organizations:ListDelegatedAdministrators",
        "organizations:RegisterDelegatedAdministrator",
      ])
    ])
    error_message = "The lambda must be granted the PutOrganizationConformancePack permissions"
  }

  assert {
    condition = anytrue(flatten([
      for s in data.aws_iam_policy_document.permissions.statement : [
        for c in coalesce(s.condition, []) : contains(s.actions, "iam:CreateServiceLinkedRole") && c.variable == "iam:AWSServiceName" && contains(c.values, "config-multiaccountsetup.amazonaws.com")
      ]
    ]))
    error_message = "iam:CreateServiceLinkedRole must be scoped to config-multiaccountsetup.amazonaws.com"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.permissions.statement : toset(s.actions) == toset(["s3:GetObject"]) && toset(s.resources) == toset(["arn:aws:s3:::tagging-conformance-pack/conformance-packs/tagging-compliance.yaml"])
    ])
    error_message = "The lambda must be able to read the conformance pack template object"
  }
}

run "organizations_module_without_conformance_pack" {
  command = plan

  module {
    source = "./modules/organizations"
  }

  variables {
    bucket_arn  = "arn:aws:s3:::tagging-compliance"
    bucket_name = "tagging-compliance"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.permissions.statement : !anytrue([for a in s.actions : startswith(a, "config:") || startswith(a, "iam:")])
    ])
    error_message = "No conformance pack permissions must be granted without a conformance pack name"
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.account_events) == 0
    error_message = "The account event rule must be disabled by default"
  }
}
