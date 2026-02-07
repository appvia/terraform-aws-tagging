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

```hcl
# In your management account (or shared services account)
module "tagging_compliance_central" {
  source = "appvia/tagging/aws"
  version = "0.0.1"

  dynamodb_table_name  = "tagging-compliance-rules"
  dynamodb_billing_mode = "PAY_PER_REQUEST"
  organization_id      = "o-123456789"  # Your AWS Organization ID

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
  source = "appvia/tagging/aws//modules/config"
  version = "0.0.1"

  # Reference the central DynamoDB table (cross-account)
  compliance_dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/tagging-compliance-rules"

  # Lambda configuration
  lambda_name        = "tagging-compliance-evaluator"
  lambda_description = "Evaluates resource tagging compliance"
  lambda_log_level   = "INFO"

  # AWS Config rule configuration
  config_name                    = "tagging-compliance"
  config_max_execution_frequency = "TwentyFour_Hours"
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

  dynamodb_table_name   = "org-tagging-compliance"
  dynamodb_billing_mode = "PAY_PER_REQUEST"
  organization_id       = data.aws_organizations_organization.current.id

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

  compliance_dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/org-tagging-compliance"

  lambda_name      = "tagging-compliance-prod"
  lambda_log_level = "INFO"
  lambda_timeout   = 60

  config_name                    = "tagging-compliance-prod"
  config_max_execution_frequency = "Six_Hours"  # More frequent in production
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

  compliance_dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/org-tagging-compliance"

  lambda_name      = "tagging-compliance-dev"
  lambda_log_level = "DEBUG"  # More verbose logging in dev

  config_name                    = "tagging-compliance-dev"
  config_max_execution_frequency = "TwentyFour_Hours"  # Less frequent in dev
  config_resource_types          = ["*"]  # Evaluate all resource types

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
  organization_id    = "o-123456789"  # For cross-account invocation

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
  dynamodb_table_arn  = module.tagging_central.dynamodb_arn

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

  dynamodb_table_arn         = "arn:aws:dynamodb:us-east-1:999999999999:table/compliance-rules"
  lambda_name                = "org-tagging-compliance"
  config_name                = "tagging-compliance-prod"
  config_max_execution_frequency = "Six_Hours"  # More frequent

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

## Cost Considerations

- **DynamoDB**: Pay-per-request pricing (~$1.25 per million reads)
- **AWS Config**: ~$0.003 per configuration item recorded
- **Lambda**: Minimal cost (typically < $5/month per account)
- **CloudWatch Logs**: Based on ingestion and storage (configure retention appropriately)

**Estimated cost for 1000 resources across 10 accounts**: ~$50-100/month

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
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dynamodb_billing_mode"></a> [dynamodb\_billing\_mode](#input\_dynamodb\_billing\_mode) | The billing mode for the DynamoDB table. Valid values are PROVISIONED and PAY\_PER\_REQUEST. | `string` | `"PAY_PER_REQUEST"` | no |
| <a name="input_dynamodb_table_kms_key_id"></a> [dynamodb\_table\_kms\_key\_id](#input\_dynamodb\_table\_kms\_key\_id) | KMS key ID for DynamoDB table encryption (optional) | `string` | `null` | no |
| <a name="input_dynamodb_table_name"></a> [dynamodb\_table\_name](#input\_dynamodb\_table\_name) | The name of the DynamoDB table to store tags for AWS resources. | `string` | `"tagging-compliance"` | no |
| <a name="input_dynamodb_table_point_in_time_recovery_enabled"></a> [dynamodb\_table\_point\_in\_time\_recovery\_enabled](#input\_dynamodb\_table\_point\_in\_time\_recovery\_enabled) | Enable point-in-time recovery for the DynamoDB table | `bool` | `false` | no |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | The ID of the AWS Organization to allow access to the DynamoDB table. | `string` | `null` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | List of compliance rules to be stored in the DynamoDB table. | <pre>list(object({<br/>    AccountIds   = optional(list(string), ["*"])<br/>    Enabled      = optional(bool, true)<br/>    Required     = optional(bool, true)<br/>    ResourceType = string<br/>    RuleId       = string<br/>    Tag          = string<br/>    ValuePattern = optional(string, null)<br/>    Values       = optional(list(string), [])<br/>  }))</pre> | `[]` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the DynamoDB table. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_dynamodb_arn"></a> [dynamodb\_arn](#output\_dynamodb\_arn) | The ARN of the DynamoDB table used for tagging compliance. |
| <a name="output_organization_id"></a> [organization\_id](#output\_organization\_id) | The ID of the AWS Organization allowed access to the DynamoDB table. |
<!-- END_TF_DOCS -->
