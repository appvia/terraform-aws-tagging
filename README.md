![Github Actions](https://github.com/appvia/terraform-aws-tagging/actions/workflows/terraform.yml/badge.svg)

# Terraform AWS Tagging Compliance Framework

## Description

A comprehensive framework for enforcing tagging compliance across AWS Organizations using centralized rule management and AWS Config custom rules. This solution enables platform teams to define tagging standards once and enforce them consistently across all accounts in an organization.

### Architecture Overview

The framework supports two deployment patterns:

#### Pattern 1: Per-Account Config Rules (Traditional)
```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Account                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Central DynamoDB Table                                   │  │
│  │  (Compliance Rules Repository)                            │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-account Read Access                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Lambda Function                                          │  │
│  │  (Evaluation Engine)                                      │  │
│  │  Allows org-wide invocation                              │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└──────────────────────┼───────────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Account A  │ │  Account B  │ │  Account C  │
│             │ │             │ │             │
│  AWS Config │ │  AWS Config │ │  AWS Config │
│     Rule    │ │     Rule    │ │     Rule    │
│      ↓      │ │      ↓      │ │      ↓      │
│  Invokes    │ │  Invokes    │ │  Invokes    │
│  Central    │ │  Central    │ │  Central    │
│   Lambda    │ │   Lambda    │ │   Lambda    │
│ (cross-acc) │ │ (cross-acc) │ │ (cross-acc) │
└─────────────┘ └─────────────┘ └─────────────┘
```

#### Pattern 2: Organization Conformance Pack (Recommended)
```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Account                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Central DynamoDB Table                                   │  │
│  │  (Compliance Rules Repository)                            │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-account Read Access                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Lambda Function                                          │  │
│  │  (Evaluation Engine)                                      │  │
│  │  Allows org-wide invocation                              │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  S3 Bucket                                                │  │
│  │  • conformance-pack.yaml template                        │  │
│  │  • Versioning enabled                                    │  │
│  │  • Encrypted with KMS                                    │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  CloudFormation StackSet                                  │  │
│  │  Deploys conformance pack to all accounts                │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└──────────────────────┼───────────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Account A  │ │  Account B  │ │  Account C  │
│             │ │             │ │             │
│ Config Rule │ │ Config Rule │ │ Config Rule │
│      ↓      │ │      ↓      │ │      ↓      │
│  Invokes    │ │  Invokes    │ │  Invokes    │
│  Central    │ │  Central    │ │  Central    │
│   Lambda    │ │   Lambda    │ │   Lambda    │
│ (via ConPack)│ │ (via ConPack)│ │ (via ConPack)│
└─────────────┘ └─────────────┘ └─────────────┘
```

### How It Works

1. **Central Rule Management**: Tagging compliance rules are defined once in a central DynamoDB table (typically in the management or shared services account)
2. **Organization-Wide Access**: The DynamoDB table has a resource policy allowing read access from all accounts in the AWS Organization
3. **Per-Account Enforcement**: Each account deploys an AWS Config custom rule with a Lambda function
4. **Real-Time Validation**: When resources are created or modified, AWS Config invokes the Lambda function
5. **Compliance Evaluation**: The Lambda reads rules from the central table and validates the resource's tags
6. **Reporting**: Compliance status is reported back to AWS Config, providing visibility in the AWS Console and enabling automated remediation

### Key Features

- **Centralized Management**: Define tagging rules once, enforce everywhere
- **Organization-Wide Scope**: Works across all accounts in an AWS Organization
- **Flexible Rules**: Support for required/optional tags, permitted values, and regex patterns
- **Organizational Path Scoping**: Target rules to specific AWS Organizations paths (e.g. `root/Sandbox`)
- **Account Scoping**: Apply different rules to different accounts (e.g., stricter rules for production)
- **Resource Type Filtering**: Target specific AWS services or resource types
- **Real-Time Enforcement**: Automatic evaluation when resources change
- **Easy Updates**: Change rules centrally without redeploying to each account
- **Compliance Reporting**: View compliance status in AWS Config console
- **Infrastructure as Code**: Fully managed through Terraform

## Modules

This framework consists of five modular components:

### 1. Root Module (This Module)
Creates the central DynamoDB table with organization-wide access policies. Deploy this in your management or shared services account.

**[Documentation](./README.md)**

### 2. Validation Module
Manages the Lambda function for evaluating tagging compliance. Handles IAM roles, permissions, and CloudWatch Logs integration. Can be shared across multiple Config rules and accounts.

**[📖 Validation Module Documentation](./modules/validation/README.md)**

### 3. Config Module
Deploys AWS Config custom rules in individual accounts. References the Lambda function from validation module to evaluate resource compliance. Can invoke Lambda in the same account or cross-account (from management account).

**[📖 Config Module Documentation](./modules/config/README.md)**

### 4. Compliance Module
Stores tagging compliance rules in the central DynamoDB table. Use this to define your organization's tagging standards that Lambda evaluates.

**[📖 Compliance Module Documentation](./modules/compliance/README.md)**

### 5. Pack Module
Wraps the Lambda evaluator into an AWS Config Conformance Pack for organization-wide or account-level distribution. Handles S3 storage, versioning, and deployment via CloudFormation StackSets.

**[📖 Pack Module Documentation](./modules/pack/README.md)**

## Usage

### Step 1: Deploy Central DynamoDB Table (Management Account)

If you plan to scope rules using `OrganizationalPaths`, you must set `var.organizations` in the root module. This creates a separate DynamoDB table for account metadata and deploys a Lambda that uses the AWS Organizations API to populate account information (including organizational paths). The compliance evaluator then uses that table to match `OrganizationalPaths` in rules.

```hcl
# In your management account (or shared services account)
module "tagging_compliance_central" {
  source  = "appvia/tagging/aws"
  version = "0.0.1"

  # Configure the compliance DynamoDB table
  compliance = {
    table = {
      name         = "tagging-compliance-rules"
      billing_mode = "PAY_PER_REQUEST"
    }
  }

  # Enable organization-wide access
  enable_organizations = true
  organizations_id     = "o-123456789"  # Your AWS Organization ID

  # Enable Organizations metadata table for OrganizationalPaths filtering
  organizations = {
    table = {
      name = "organizational-accounts"
    }
  }

  # Define compliance rules centrally
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
      RuleId       = "require-cost-center-prod"
      ResourceType = "AWS::*"
      Tag          = "CostCenter"
      Required     = true
      ValuePattern = "^CC-[0-9]{4}$"
      AccountIds   = ["111222333444"]  # Production account only
      Enabled      = true
    },
    {
      RuleId              = "require-owner-email-sandbox"
      ResourceType        = "AWS::*"
      Tag                 = "Owner"
      Required            = true
      ValuePattern        = "^[a-zA-Z0-9._%+-]+@company\\.com$"
      OrganizationalPaths = ["root/Sandbox"]
      Enabled             = true
    }
  ]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

output "dynamodb_table_arn" {
  value = module.tagging_compliance_central.dynamodb_arn
}
```

### Step 2: Deploy Config Rules (Each Account)

```hcl
# In each member account that should enforce compliance
module "tagging_compliance_evaluator" {
  source  = "appvia/tagging/aws//modules/config"
  version = "0.0.1"

  # Reference the central DynamoDB table (cross-account)
  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/tagging-compliance-rules"

  # Lambda configuration
  lambda_name        = "tagging-compliance-evaluator"
  lambda_description = "Evaluates resource tagging compliance"
  lambda_log_level   = "INFO"

  # AWS Config rule configuration
  config_name           = "tagging-compliance"
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function"
  ]

  # CloudWatch Logs
  cloudwatch_logs_retention_in_days = 14
  cloudwatch_logs_kms_key_id        = null  # Optional: KMS key for encryption

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Step 3: Add or Update Rules (Anytime)

```hcl
# Update rules in the management account - changes apply to all accounts automatically
module "tagging_compliance_rules" {
  source = "appvia/tagging/aws//modules/compliance"
  version = "0.0.1"

  dynamodb_table_name = "tagging-compliance-rules"

  rules = [
    {
      RuleId       = "new-data-classification-rule"
      ResourceType = "AWS::S3::Bucket"
      Tag          = "DataClassification"
      Required     = true
      Values       = ["public", "internal", "confidential", "restricted"]
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}
```

## Complete Multi-Account Example

Here's a complete example showing deployment across a typical AWS Organization:

### Management Account (`management-account/tagging.tf`)

```hcl
# Create central DynamoDB table and define organization-wide rules
module "tagging_compliance" {
  source = "appvia/tagging/aws"

  # Configure the compliance DynamoDB table
  compliance = {
    table = {
      name         = "org-tagging-compliance"
      billing_mode = "PAY_PER_REQUEST"
    }
  }

  # Enable organization-wide access
  enable_organizations = true
  organizations_id     = data.aws_organizations_organization.current.id

  rules = [
    # Global rules for all accounts
    {
      RuleId       = "global-environment-tag"
      ResourceType = "AWS::*"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development", "sandbox"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    {
      RuleId       = "global-owner-tag"
      ResourceType = "AWS::*"
      Tag          = "Owner"
      Required     = true
      ValuePattern = "^[a-zA-Z0-9._%+-]+@company\\.com$"
      AccountIds   = ["*"]
      Enabled      = true
    },
    {
      RuleId       = "global-managed-by-tag"
      ResourceType = "AWS::*"
      Tag          = "ManagedBy"
      Required     = true
      Values       = ["terraform", "cloudformation", "console"]
      AccountIds   = ["*"]
      Enabled      = true
    },
    # Production-specific rules
    {
      RuleId       = "prod-cost-center"
      ResourceType = "AWS::*"
      Tag          = "CostCenter"
      Required     = true
      ValuePattern = "^CC-[0-9]{4}$"
      AccountIds   = ["111222333444"]  # Production account
      Enabled      = true
    },
    {
      RuleId       = "prod-compliance"
      ResourceType = "AWS::*"
      Tag          = "Compliance"
      Required     = true
      Values       = ["sox", "pci", "hipaa", "none"]
      AccountIds   = ["111222333444"]
      Enabled      = true
    }
  ]

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
    Purpose     = "tagging-compliance"
  }
}

output "compliance_table_arn" {
  value       = module.tagging_compliance.dynamodb_arn
  description = "ARN of the central compliance rules table"
}
```

### Production Account (`production-account/config-rules.tf`)

```hcl
# Deploy AWS Config rule to enforce compliance in production account
module "tagging_evaluator" {
  source = "appvia/tagging/aws//modules/config"

  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/org-tagging-compliance"

  lambda_name      = "tagging-compliance-prod"
  lambda_log_level = "INFO"
  lambda_timeout   = 60

  config_name           = "tagging-compliance-prod"
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::EC2::SecurityGroup",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::Lambda::Function",
    "AWS::DynamoDB::Table",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service"
  ]

  cloudwatch_logs_retention_in_days = 30  # Longer retention for production
  cloudwatch_logs_kms_key_id        = aws_kms_key.logs.id

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Development Account (`development-account/config-rules.tf`)

```hcl
# Deploy AWS Config rule to enforce compliance in development account
module "tagging_evaluator" {
  source = "appvia/tagging/aws//modules/config"

  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/org-tagging-compliance"

  lambda_name      = "tagging-compliance-dev"
  lambda_log_level = "DEBUG"  # More verbose logging in dev

  config_name           = "tagging-compliance-dev"
  config_resource_types = ["*"]  # Evaluate all resource types

  cloudwatch_logs_retention_in_days = 7  # Shorter retention for dev

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
```

## Rule Examples

### Basic Required Tags

```hcl
{
  RuleId       = "require-environment"
  ResourceType = "AWS::EC2::Instance"
  Tag          = "Environment"
  Required     = true
  Values       = ["production", "staging", "development"]
  AccountIds   = ["*"]
  Enabled      = true
}
```

### Email Pattern Validation

```hcl
{
  RuleId       = "validate-owner-email"
  ResourceType = "AWS::*"
  Tag          = "Owner"
  Required     = true
  ValuePattern = "^[a-zA-Z0-9._%+-]+@(company\\.com|partner\\.com)$"
  Values       = []
  AccountIds   = ["*"]
  Enabled      = true
}
```

### Account-Specific Rules

```hcl
{
  RuleId       = "prod-cost-tracking"
  ResourceType = "AWS::*"
  Tag          = "CostCenter"
  Required     = true
  ValuePattern = "^CC-[0-9]{4}$"
  AccountIds   = ["111222333444", "555666777888"]  # Prod accounts only
  Enabled      = true
}
```

### Optional Tags

```hcl
{
  RuleId       = "optional-project"
  ResourceType = "AWS::Lambda::Function"
  Tag          = "Project"
  Required     = false  # Only validate if present
  Values       = ["web-app", "api", "data-pipeline"]
  AccountIds   = ["*"]
  Enabled      = true
}
```

## Monitoring and Compliance

### View Compliance in AWS Console

1. Navigate to **AWS Config** in each account
2. Go to **Rules** → **tagging-compliance**
3. View compliant and non-compliant resources
4. Click on resources to see detailed evaluation results

### Query with CloudWatch Logs Insights

```
fields @timestamp, compliance_type, resource_type, resource_id
| filter action = "lambda_handler"
| stats count() by compliance_type, resource_type
| sort count desc
```

### AWS CLI Commands

```bash
# Check rule compliance status
aws configservice describe-compliance-by-config-rule \
  --config-rule-names tagging-compliance

# Get non-compliant resources
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name tagging-compliance \
  --compliance-types NON_COMPLIANT

# Evaluate a specific resource
aws configservice get-resource-config-history \
  --resource-type AWS::EC2::Instance \
  --resource-id i-1234567890abcdef0
```

## Deployment Patterns

### Pattern 1: Individual Config Rules Per Account (Traditional)

Each account deploys its own Config rules via the `config` module:

```hcl
# In each member account
module "tagging_config" {
  source = "appvia/tagging/aws//modules/config"

  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/compliance-rules"
  lambda_name        = "org-tagging-compliance"
  config_name        = "tagging-compliance"

  tags = { Environment = "production" }
}
```

**Pros:**
- Fine-grained control per account
- Can customize rules per account
- Easier troubleshooting per account

**Cons:**
- Must deploy to each account separately
- More Terraform state management

### Pattern 2: Organization Conformance Pack (Recommended)

Use the `pack` module to deploy organization-wide via CloudFormation StackSet:

```hcl
# In management account
module "tagging_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance"
  s3_bucket_name           = "org-conformance-packs-${data.aws_caller_identity.current.account_id}"
  deploy_organization_wide = true

  lambda_function_arn = module.validation.lambda_arn
  dynamodb_table_arn  = module.tagging_compliance.dynamodb_arn

  excluded_accounts = ["111111111111"]  # Sandbox accounts

  tags = { Environment = "management" }
}
```

**Pros:**
- Single deployment for entire organization
- Automatic deployment to new accounts
- Centralized version control via S3
- Self-service compliance for business units

**Cons:**
- Less granular control per account
- Requires AWS Organizations

### Pattern 3: Hybrid Approach

Use pack for most accounts, individual config rules for special cases:

```hcl
# Management account
module "tagging_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance"
  s3_bucket_name           = "org-conformance-packs"
  deploy_organization_wide = true
  excluded_accounts        = ["111111111111", "222222222222"]  # Custom configs

  # ... other config
}

# Production account (custom config)
module "tagging_config_prod" {
  source = "appvia/tagging/aws//modules/config"

  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/compliance-rules"
  lambda_name        = "org-tagging-compliance"
  config_name        = "tagging-compliance-prod"

  # ... other config
}
```

## Best Practices

1. **Start with Observability**: Use `Required = false` initially to understand current state
2. **Test in Non-Production**: Validate rules in dev/test accounts before production
3. **Use Descriptive RuleIds**: Make rules easy to identify (e.g., `"prod-require-cost-center"`)
4. **Document Patterns**: Add comments explaining complex regex patterns
5. **Version Control**: Store Terraform code in Git for audit trail
6. **Gradual Enablement**: Enable rules incrementally to avoid overwhelming teams
7. **Monitor Compliance**: Set up dashboards and alerts for compliance metrics
8. **Regular Reviews**: Periodically review and update rules as requirements change
9. **Account Scoping**: Use stricter rules in production accounts
10. **Automated Remediation**: Consider building automated remediation for common violations

## Troubleshooting

### Lambda Function Errors

Check CloudWatch Logs for the Lambda function:
```bash
aws logs tail /aws/lambda/tagging-compliance-evaluator --follow
```

### DynamoDB Access Issues

Verify the organization ID and resource policy:
```bash
aws dynamodb get-resource-policy --resource-arn <table-arn>
```

### Config Rule Not Triggering

Check Config recorder status:
```bash
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
```

### Resource Not Evaluated

Verify the resource type is in the Config rule scope:
```bash
aws configservice describe-config-rules --config-rule-names tagging-compliance
```

## DynamoDB Capacity Planning

### Understanding RCU and WCU

DynamoDB uses two billing metrics to measure capacity:

- **Read Capacity Units (RCU)**: One RCU represents one strongly consistent read per second of items up to 4 KB in size. If you need to read larger items or use eventually consistent reads, the calculation changes accordingly. See [AWS DynamoDB Read/Write Capacity Mode](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html) for details.

- **Write Capacity Units (WCU)**: One WCU represents one write per second of items up to 1 KB in size. Larger items consume proportionally more WCUs. See [AWS DynamoDB Provisioned Throughput](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ProvisionedThroughput.html) for details.

**Billing Modes:**
- **On-Demand**: Pay per request (~$1.25 per million reads, ~$6.25 per million writes). Best for unpredictable workloads
- **Provisioned**: Reserve capacity upfront (cheaper for predictable workloads). This framework defaults to `PAY_PER_REQUEST`

### Capacity Estimation Formula

Your DynamoDB capacity depends on:

1. **Number of AWS Accounts**: `N_accounts`
2. **Resource Types in Scope**: `N_resource_types` (e.g., EC2, S3, RDS)
3. **Total Resources**: `N_resources` (average per account)
4. **Resource Change Frequency**: `changes_per_day` (creation/modification rate)
5. **Config Evaluation Frequency**: `evaluation_interval` (Six_Hours, TwentyFour_Hours, etc.)

**Estimated Reads per Lambda Invocation**: 2-3 reads
- 1 read to scan/query compliance rules
- 1 read per resource type for rule matching

**Estimated Writes per Lambda Invocation**: ~1 write
- Optional: Update compliance state in DynamoDB (or use AWS Config for state)

**Capacity Calculation:**
```
Daily Reads = (N_accounts × N_resources × changes_per_day × 2.5)
            + (N_accounts × N_resources × (24 ÷ evaluation_interval_hours))

Daily Writes = (N_accounts × N_resources × changes_per_day × 1)
             + (rule_updates_per_day)

RCU = (Daily Reads ÷ 86,400 seconds) × 1.5  # 1.5x buffer for spikes
WCU = (Daily Writes ÷ 86,400 seconds) × 1.5 # 1.5x buffer for spikes
```

Note the AWS Config rule can be configured to use caching on the ruleset to greatly reduce associated costs, with the downside being the additional time is now takes to roll changes to the rules.

### Cost Optimization Tips

1. **Start with On-Demand**: Use the default `PAY_PER_REQUEST` billing mode to test your workload
2. **Monitor CloudWatch Metrics**: Track consumed capacity over 2-4 weeks
3. **Consider Provisioned Mode**: Switch to provisioned if consistent reads exceed 1M/day
4. **Enable TTL**: Set a time-to-live on compliance history items to automatically delete old data
5. **Rule Caching**: The Lambda handler implements in-memory caching to reduce DynamoDB reads by 80%+
6. **DAX Consideration**: For very large deployments, consider DynamoDB Accelerator (DAX) for additional caching

### Changing Billing Mode

```hcl
# Switch from on-demand to provisioned (update variables)
module "tagging_compliance_central" {
  source = "appvia/tagging/aws"

  compliance = {
    table = {
      name           = "tagging-compliance-rules"
      billing_mode   = "PROVISIONED"
      read_capacity  = 100
      write_capacity = 20
    }
  }

  # ... other variables
}
```

## Update Documentation

The `terraform-docs` utility is used to generate this README. Follow the below steps to update:

1. Make changes to the `.terraform-docs.yml` file
2. Fetch the `terraform-docs` binary (https://terraform-docs.io/user-guide/installation/)
3. Run `terraform-docs markdown table --output-file ${PWD}/README.md --output-mode inject .`
3. Run `terraform-docs markdown table --output-file ${PWD}/README.md --output-mode inject .`

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_compliance"></a> [compliance](#input\_compliance) | Configuration for the compliance feature. | <pre>object({<br/>    table = object({<br/>      ## The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY_PER_REQUEST.<br/>      billing_mode = optional(string, "PAY_PER_REQUEST")<br/>      ## The KMS key ID or ARN to use for server-side encryption of the DynamoDB table.<br/>      kms_key_id = optional(string, null)<br/>      ## The name of the DynamoDB table to store compliance rules.<br/>      name = optional(string, "tagging-compliance")<br/>      ## Whether to enable point-in-time recovery for the DynamoDB table. Defaults to false.<br/>      point_in_time_recovery_enabled = optional(bool, false)<br/>      ## The read capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).<br/>      read_capacity = optional(number, null)<br/>      ## The write capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).<br/>      write_capacity = optional(number, null)<br/>    })<br/>  })</pre> | <pre>{<br/>  "table": {}<br/>}</pre> | no |
| <a name="input_enable_organizations"></a> [enable\_organizations](#input\_enable\_organizations) | Enable organization access to the DynamoDB table. When enabled, allows any account in the organization to access the table. | `bool` | `true` | no |
| <a name="input_organizations"></a> [organizations](#input\_organizations) | Configuration for the organizations table and lambda. | <pre>object({<br/>    table = object({<br/>      ## The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY_PER_REQUEST.<br/>      billing_mode = optional(string, "PAY_PER_REQUEST")<br/>      ## The KMS key ID or ARN to use for server-side encryption of the DynamoDB table.<br/>      kms_key_id = optional(string, null)<br/>      ## The name of the DynamoDB table to store organization metadata for AWS resources.<br/>      name = optional(string, "organization-compliance")<br/>      ## Whether to enable point-in-time recovery for the DynamoDB table. Defaults to false.<br/>      point_in_time_recovery_enabled = optional(bool, false)<br/>      ## The read capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).<br/>      read_capacity = optional(number, null)<br/>      ## The write capacity units for the DynamoDB table (only applicable if billing_mode is PROVISIONED).<br/>      write_capacity = optional(number, null)<br/>    }),<br/>    lambda = optional(object({<br/>      ## The description of the Lambda function to handle AWS Organization account movements.<br/>      description = optional(string, "Handles AWS Organization account movements for tagging compliance.")<br/>      ## The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL.<br/>      log_level = optional(string, "INFO")<br/>      ## The amount of memory in MB allocated to the Lambda function.<br/>      memory_size = optional(number, 128)<br/>      ## The name of the Lambda function to handle AWS Organization account movements.<br/>      name = optional(string, "organization-compliance")<br/>      ## The runtime environment for the Lambda function.<br/>      role_name = optional(string, "organization-compliance")<br/>      ## The runtime environment for the Lambda function.<br/>      runtime = optional(string, "python3.12")<br/>      ## The timeout for the Lambda function in seconds.<br/>      timeout = optional(number, 30)<br/>    }), {})<br/>  })</pre> | `null` | no |
| <a name="input_organizations_id"></a> [organizations\_id](#input\_organizations\_id) | AWS Organization ID to allow access to the DynamoDB table/s | `string` | `null` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | List of compliance rules to be stored in the DynamoDB table. | <pre>list(object({<br/>    AccountIds          = optional(list(string), [])<br/>    Enabled             = optional(bool, true)<br/>    Required            = optional(bool, true)<br/>    ResourceType        = string<br/>    RuleId              = string<br/>    Tag                 = string<br/>    ValuePattern        = optional(string, null)<br/>    Values              = optional(list(string), [])<br/>    OrganizationalPaths = optional(list(string), [])<br/>  }))</pre> | `[]` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the DynamoDB table. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_dynamodb_table_arn"></a> [dynamodb\_table\_arn](#output\_dynamodb\_table\_arn) | The ARN of the DynamoDB table used for tagging compliance. |
| <a name="output_dynamodb_table_name"></a> [dynamodb\_table\_name](#output\_dynamodb\_table\_name) | The name of the DynamoDB table used for tagging compliance. |
| <a name="output_organizations_id"></a> [organizations\_id](#output\_organizations\_id) | The ID of the AWS Organization allowed access to the DynamoDB table. |
| <a name="output_organizations_lambda_arn"></a> [organizations\_lambda\_arn](#output\_organizations\_lambda\_arn) | The ARN of the Lambda function used for handling organization account movements. |
| <a name="output_organizations_lambda_name"></a> [organizations\_lambda\_name](#output\_organizations\_lambda\_name) | The name of the Lambda function used for handling organization account movements. |
| <a name="output_organizations_table_arn"></a> [organizations\_table\_arn](#output\_organizations\_table\_arn) | The ARN of the DynamoDB table used for storing organization metadata. |
| <a name="output_organizations_table_name"></a> [organizations\_table\_name](#output\_organizations\_table\_name) | The name of the DynamoDB table used for storing organization metadata. |
<!-- END_TF_DOCS -->
