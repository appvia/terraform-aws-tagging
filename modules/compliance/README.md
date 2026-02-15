# Tagging Compliance Rules Module

## Introduction

This Terraform module manages tagging compliance rules by storing them in a DynamoDB table. These rules define which tags are required or optional for AWS resources, specify permitted tag values, and can be scoped to specific AWS accounts, organizational paths, or resource types. The rules stored by this module are consumed by the AWS Config custom rule (see the `config` module) to evaluate resource compliance.

When you use `OrganizationalPaths` in rules, you must enable the Organizations integration by setting `var.organizations`. This creates a separate DynamoDB table that stores account metadata, which is populated by a Lambda function that calls the AWS Organizations API to retrieve account information (including organizational paths). The compliance evaluation uses that table to match `OrganizationalPaths`.

### Key Features

- **Declarative Rule Management**: Define all tagging rules as Terraform code
- **Flexible Rule Definitions**: Support for:
  - Required vs. optional tags
  - Specific permitted values or regex patterns
  - Account-scoped or organizational path-scoped rules
  - Resource-type specific or wildcard rules
  - Enable/disable rules without deletion
- **DynamoDB Integration**: Automatically stores rules in the format expected by AWS Config Lambda
- **Version Control**: Track rule changes through your Git history
- **Immutable Infrastructure**: Rules are fully managed by Terraform

### Module Purpose

This module is designed to work in conjunction with the `config` module:
1. **Compliance Module** (this module) → Stores tagging rules in DynamoDB
2. **Config Module** → Creates AWS Config rule + Lambda that reads rules from DynamoDB and evaluates resources

## Usage

### Basic Example

```hcl
module "tagging_compliance_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    {
      RuleId       = "require-environment-tag"
      ResourceType = "AWS::EC2::*"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development", "sandbox"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    {
      RuleId       = "require-owner-email"
      ResourceType = "AWS::*"
      Tag          = "Owner"
      Required     = true
      ValuePattern = "^[a-zA-Z0-9._%+-]+@company\\.com$"
      AccountIds   = ["*"]
      Enabled      = true
    },
    {
      RuleId               = "require-owner-email-production"
      ResourceType         = "AWS::*"
      Tag                  = "Owner"
      Required             = true
      ValuePattern         = "^[a-zA-Z0-9._%+-]+@company\\.com$"
      OrganizationalPaths  = ["/root/workloads/production"]
      Enabled              = true
    }
  ]
}
```

### Complete Example with DynamoDB Table

```hcl
# DynamoDB table to store tagging rules
resource "aws_dynamodb_table" "tagging_rules" {
  name           = "tagging-compliance-rules"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "RuleId"
  range_key      = "ResourceType"

  attribute {
    name = "RuleId"
    type = "S"
  }

  attribute {
    name = "ResourceTypes"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Store compliance rules in the table
module "tagging_compliance_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = aws_dynamodb_table.tagging_rules.name

  rules = [
    {
      RuleId        = "require-environment-tag"
      ResourceTypes = ["AWS::EC2::Instance"]
      Tag           = "Environment"
      Required      = true
      Values        = ["production", "staging", "development"]
      AccountIds    = ["*"]
      Enabled       = true
    },
    {
      RuleId        = "optional-cost-center"
      ResourceTypes = ["AWS::RDS::DBInstance"]
      Tag           = "CostCenter"
      Required      = false
      Values        = ["CC-001", "CC-002", "CC-003"]
      AccountIds    = ["123456789012"]
      Enabled       = true
    }
  ]
}
```

## Rule Configuration Reference

Each rule object supports the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `RuleId` | string | **Yes** | — | Unique identifier for the rule (used as DynamoDB partition key). |
| `ResourceType` | string | **Yes** | — | AWS resource type (e.g., `"AWS::EC2::Instance"`, `"AWS::EC2::*"`). Use `"*"` for all types. |
| `Tag` | string | **Yes** | — | Tag key to evaluate (e.g., `"Environment"`, `"Owner"`). |
| `AccountIds` | list(string) | No | `["*"]` | List of AWS account IDs. Use `["*"]` for all accounts. |
| `OrganizationalPaths` | list(string) | No | `[]` | List of AWS Organizations paths (e.g., `["/root/workloads/production"]`). Use `["*"]` for all OUs. Requires `var.organizations` to be enabled. |
| `Enabled` | bool | No | `true` | Whether the rule is active. Set to `false` to temporarily disable. |
| `Required` | bool | No | `true` | Whether the tag must be present. Set to `false` to only validate if present. |
| `ValuePattern` | string | No | `null` | Optional regex pattern for validating tag values. Takes precedence over `Values`. |
| `Values` | list(string) | No | `[]` | List of permitted tag values. Ignored if `ValuePattern` is set. |

## Examples

### Example 1: Enforce Environment Tags Across All EC2 Resources

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    {
      RuleId       = "enforce-environment-tag-ec2"
      ResourceType = "AWS::EC2::*"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development", "sandbox"]
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}
```

### Example 2: Enforce Owner Email Pattern

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    {
      RuleId       = "enforce-owner-email-pattern"
      ResourceType = "AWS::*"
      Tag          = "Owner"
      Required     = true
      ValuePattern = "^[a-zA-Z0-9._%+-]+@(company\\.com|partner\\.com)$"
      Values       = []  # Ignored when ValuePattern is set
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}
```

### Example 3: Multiple Rules for Different Resource Types

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    # All EC2 instances must have Environment tag
    {
      RuleId       = "ec2-environment-tag"
      ResourceType = "AWS::EC2::Instance"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # All S3 buckets must have DataClassification tag
    {
      RuleId       = "s3-data-classification"
      ResourceType = "AWS::S3::Bucket"
      Tag          = "DataClassification"
      Required     = true
      Values       = ["public", "internal", "confidential", "restricted"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # RDS instances should have optional BackupSchedule tag
    {
      RuleId       = "rds-backup-schedule"
      ResourceType = "AWS::RDS::DBInstance"
      Tag          = "BackupSchedule"
      Required     = false  # Optional tag
      Values       = ["daily", "weekly", "monthly", "none"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # Lambda functions in production account must have Team tag
    {
      RuleId       = "lambda-team-tag-prod"
      ResourceType = "AWS::Lambda::Function"
      Tag          = "Team"
      Required     = true
      Values       = ["platform", "data", "security", "app"]
      AccountIds   = ["111222333444"]  # Production account only
      Enabled      = true
    }
  ]
}
```

### Example 4: Account-Specific Rules

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    # Production account: Strict cost tracking
    {
      RuleId       = "prod-cost-center"
      ResourceType = "AWS::*"
      Tag          = "CostCenter"
      Required     = true
      ValuePattern = "^CC-[0-9]{4}$"  # Must match CC-NNNN format
      AccountIds   = ["111222333444"]
      Enabled      = true
    },
    # Development accounts: Flexible owner tracking
    {
      RuleId       = "dev-owner-tag"
      ResourceType = "AWS::*"
      Tag          = "Owner"
      Required     = false  # Optional in dev
      Values       = []
      AccountIds   = ["555666777888", "999000111222"]
      Enabled      = true
    }
  ]
}
```

### Example 5: Wildcard Resource Type Matching

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    # All EC2 resources (instances, volumes, snapshots, etc.)
    {
      RuleId       = "ec2-all-resources-project"
      ResourceType = "AWS::EC2::*"
      Tag          = "Project"
      Required     = true
      Values       = ["web-app", "api", "data-pipeline", "infrastructure"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # All resources across all services
    {
      RuleId       = "global-managed-by"
      ResourceType = "AWS::*"
      Tag          = "ManagedBy"
      Required     = true
      Values       = ["terraform", "cloudformation", "manual"]
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}
```

### Example 6: Temporarily Disable a Rule

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    # Active rule
    {
      RuleId       = "active-environment-tag"
      ResourceType = "AWS::EC2::Instance"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # Temporarily disabled during migration
    {
      RuleId       = "disabled-legacy-tag"
      ResourceType = "AWS::EC2::Instance"
      Tag          = "LegacyTag"
      Required     = true
      Values       = ["value1", "value2"]
      AccountIds   = ["*"]
      Enabled      = false  # Disabled
    }
  ]
}
```

### Example 7: Organizational Path-Specific Rules

```hcl
module "tagging_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    # Production workloads require strict cost tracking
    {
      RuleId              = "prod-ou-cost-center"
      ResourceType        = "AWS::*"
      Tag                 = "CostCenter"
      Required            = true
      ValuePattern        = "^CC-[0-9]{4}$"  # Must match CC-NNNN format
      OrganizationalPaths = ["/root/workloads/production"]
      Enabled             = true
    },
    # Development OUs have flexible tagging
    {
      RuleId              = "dev-ou-owner"
      ResourceType        = "AWS::*"
      Tag                 = "Owner"
      Required            = false  # Optional in dev
      OrganizationalPaths = ["/root/workloads/development", "/root/sandboxes"]
      Enabled             = true
    },
    # Security OU requires compliance tags
    {
      RuleId              = "security-ou-compliance"
      ResourceType        = "AWS::*"
      Tag                 = "ComplianceLevel"
      Required            = true
      Values              = ["high", "critical"]
      OrganizationalPaths = ["/root/security"]
      Enabled             = true
    }
  ]
}
```

## Integration with Config Module

This module is designed to work with the `config` module. Here's a complete example:

```hcl
# Step 1: Create DynamoDB table
resource "aws_dynamodb_table" "tagging_rules" {
  name           = "tagging-compliance-rules"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "RuleId"
  range_key      = "ResourceType"

  attribute {
    name = "RuleId"
    type = "S"
  }

  attribute {
    name = "ResourceType"
    type = "S"
  }

  tags = {
    Environment = "production"
  }
}

# Step 2: Store compliance rules
module "compliance_rules" {
  source = "./modules/compliance"

  dynamodb_table_name = aws_dynamodb_table.tagging_rules.name

  rules = [
    {
      RuleId       = "require-environment"
      ResourceType = "AWS::EC2::Instance"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development"]
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}

# Step 3: Create AWS Config rule to evaluate compliance
module "config_rule" {
  source = "./modules/config"

  compliance_dynamodb_table_arn = aws_dynamodb_table.tagging_rules.arn

  lambda_name   = "tagging-compliance-evaluator"
  config_name   = "tagging-compliance"
  config_resource_types = ["AWS::EC2::Instance"]

  depends_on = [module.compliance_rules]
}
```

## DynamoDB Table Schema

The module expects a DynamoDB table with the following schema:

```hcl
resource "aws_dynamodb_table" "tagging_rules" {
  name         = "tagging-compliance-rules"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "RuleId"
  range_key    = "ResourceType"

  attribute {
    name = "RuleId"
    type = "S"
  }

  attribute {
    name = "ResourceType"
    type = "S"
  }
}
```

**Note**: The composite key (`RuleId` + `ResourceType`) ensures each rule is unique per resource type.

## Rule Evaluation Logic

Rules stored by this module are evaluated by the AWS Config Lambda function as follows:

1. **Matching**: Rules are matched against resources based on `ResourceType`, `AccountIds`, and `Enabled` status
2. **Tag Check**: If `Required = true`, the tag must exist on the resource
3. **Value Validation**:
   - If `ValuePattern` is set, the tag value must match the regex
   - Otherwise, if `Values` is non-empty, the tag value must be in the list
4. **Result**: Resources are marked as COMPLIANT, NON_COMPLIANT, or NOT_APPLICABLE

## Best Practices

1. **Use Descriptive RuleIds**: Choose clear, meaningful rule identifiers (e.g., `"require-environment-tag-ec2"`)
2. **Start Permissive**: Begin with `Required = false` to identify current gaps before enforcing
3. **Test in Non-Production**: Validate rules in development/staging accounts first
4. **Use Wildcards Carefully**: `AWS::*` applies to ALL resource types across all services
5. **Document ValuePatterns**: Add comments explaining complex regex patterns
6. **Version Control**: Store rules in Git to track changes and enable peer review
7. **Gradual Rollout**: Enable rules incrementally to avoid overwhelming teams
8. **Account Scoping**: Use `AccountIds` to enforce stricter rules in production accounts

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_compliance_rule_table_name"></a> [compliance\_rule\_table\_name](#input\_compliance\_rule\_table\_name) | The name of the DynamoDB table to store tags for AWS resources. | `string` | n/a | yes |
| <a name="input_rules"></a> [rules](#input\_rules) | List of compliance rules to be stored in the DynamoDB table. | <pre>list(object({<br/>    AccountIds          = optional(list(string), ["*"])<br/>    Enabled             = optional(bool, true)<br/>    OrganizationalPaths = optional(list(string), [])<br/>    Required            = optional(bool, true)<br/>    ResourceTypes       = list(string)<br/>    RuleId              = string<br/>    Tag                 = string<br/>    ValuePattern        = optional(string, "")<br/>    Values              = optional(list(string), [])<br/>  }))</pre> | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_entities"></a> [entities](#output\_entities) | The list of entities for the tagging compliance rules stored in the DynamoDB table. |
| <a name="output_rules"></a> [rules](#output\_rules) | List of all the rendered DynamoDB item rules. |
<!-- END_TF_DOCS -->