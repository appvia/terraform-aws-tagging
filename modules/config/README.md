# AWS Config Tagging Compliance Module

## Introduction

This Terraform module provisions an AWS Config custom rule that evaluates tagging compliance across your AWS resources. It integrates with a separate validation Lambda module that retrieves tagging rules from a DynamoDB table and automatically evaluates resources against those rules, marking them as compliant or non-compliant based on required tags and their values.

### Key Features

- **Modular Architecture**: Separates AWS Config rules from Lambda function management
- **Custom AWS Config Rules**: Automatically evaluate resources for tagging compliance
- **Flexible Rule Configuration**: Define rules via DynamoDB with support for:
  - Required vs. optional tags
  - Specific permitted tag values
  - Regex pattern matching for tag values
  - Account-specific or global rules
  - Enabled/disabled rule toggles
- **Cross-Account Lambda Support**: Allow any account in your organization to invoke the Lambda
- **Structured Logging**: JSON-formatted logs for easy integration with CloudWatch Logs Insights
- **IAM Best Practices**: Minimal permissions with least-privilege access
- **Encryption Support**: Optional KMS encryption for CloudWatch Logs
- **Configurable Evaluation Frequency**: Control how often resources are evaluated

### Module Components

- **AWS Lambda Function**: Python-based handler deployed via `../validation` module that evaluates resource tags against rules stored in DynamoDB
- **AWS Config Custom Rule**: Invokes the Lambda function to assess resource compliance
- **Lambda Permissions**: Grants cross-account and organization-wide invocation rights
- **CloudWatch Logs**: Structured JSON logging with optional encryption and retention policies

## Architecture

The config module now uses a separated validation module:

```
┌──────────────────────────────┐
│   Config Module (main.tf)     │
│                               │
│  • Config custom rules        │
│  • Lambda permissions         │
│  • Cross-account access       │
└────────────┬──────────────────┘
             │
             │ Calls
             ▼
┌──────────────────────────────┐
│  Validation Module            │
│                               │
│  • Lambda function            │
│  • IAM role & policy          │
│  • CloudWatch logs            │
│  • DynamoDB integration       │
└──────────────────────────────┘
```

## Usage

### Basic Example (Same Account)

```hcl
module "config_tagging_compliance" {
  source = "./modules/config"

  # DynamoDB table containing tagging rules
  dynamodb_table_arn = aws_dynamodb_table.tagging_rules.arn

  # Lambda configuration (passed to validation module)
  lambda_name        = "tagging-compliance-handler"
  lambda_description = "Evaluates tagging compliance for AWS resources"
  lambda_runtime     = "python3.12"
  lambda_timeout     = 30
  lambda_log_level   = "INFO"
  lambda_role_name   = "tagging-compliance-lambda-role"

  # AWS Config rule configuration
  config_name                    = "tagging-compliance"
  config_max_execution_frequency = "TwentyFour_Hours"
  config_resource_types          = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::RDS::DBInstance"]

  # CloudWatch Logs configuration
  cloudwatch_logs_retention_in_days = 7
  cloudwatch_logs_log_group_class   = "STANDARD"

  # Tags to apply to all resources
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Lambda and Config Separation

The `config` module now delegates Lambda function management to the `validation` module for better separation of concerns:

- **config module**: Manages AWS Config rules and Lambda permissions
- **validation module**: Manages Lambda function, IAM roles, and logging

This allows you to:
- Share a single Lambda across multiple Config rules
- Manage Lambda and Config separately
- Reuse the validation module for other purposes

If you need to customize the Lambda function beyond what this module provides, you can directly use the validation module.

### Rule Configuration in DynamoDB

The compliance rules are stored in a DynamoDB table with the following structure:

```hcl
# Example: Require an Environment tag with specific values
{
  AccountIds  = ["*"]                    # Apply to all accounts
  Enabled     = true                     # Rule is active
  Required    = true                     # Tag must be present
  ResourceType = "AWS::EC2::*"           # Applies to all EC2 resources
  Tag         = "Environment"            # Tag key to check
  ValuePattern = ""                      # No regex pattern
  Values      = ["Production", "Staging", "Development"]  # Permitted values
}

# Example: Optional tag with email pattern matching
{
  AccountIds   = ["123456789012"]        # Specific account only
  Enabled      = true
  Required     = false                   # Tag is optional
  ResourceType = "AWS::EC2::Instance"    # Specific resource type
  Tag          = "Owner"
  ValuePattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"  # Email regex
  Values       = []                      # No specific values
}
```

## Rule Definition Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `AccountIds` | list(string) | No | `["*"]` | AWS account IDs to apply rule to. Use `"*"` for all accounts. |
| `Enabled` | bool | No | `true` | Whether the rule is active. Set to `false` to disable without deleting. |
| `Required` | bool | No | `true` | Whether the tag must be present. Set to `false` to only validate if present. |
| `ResourceType` | string | Yes | — | AWS resource type pattern (e.g., `"AWS::EC2::*"`, `"AWS::S3::Bucket"`). Use `"*"` for all types. |
| `Tag` | string | Yes | — | Tag key to evaluate (e.g., `"Environment"`, `"Owner"`). |
| `ValuePattern` | string | No | `""` | Optional regex pattern for validating tag values. |
| `Values` | list(string) | No | `[]` | List of permitted tag values (ignored if `ValuePattern` is set). |

## Examples

### Example 1: Enforce Environment Tags

```hcl
# Store rule in DynamoDB
resource "aws_dynamodb_table_item" "environment_tag_rule" {
  table_name = aws_dynamodb_table.tagging_rules.name
  item = jsonencode({
    ResourceType = { S = "AWS::EC2::*" }
    Tag          = { S = "Environment" }
    Enabled      = { BOOL = true }
    Required     = { BOOL = true }
    Values       = { SS = ["production", "staging", "development", "sandbox"] }
    AccountIds   = { SS = ["*"] }
  })
}
```

### Example 2: Enforce Owner Email Tag (Pattern-based)

```hcl
# Store rule in DynamoDB
resource "aws_dynamodb_table_item" "owner_email_rule" {
  table_name = aws_dynamodb_table.tagging_rules.name
  item = jsonencode({
    ResourceType  = { S = "AWS::*" }
    Tag           = { S = "Owner" }
    Enabled       = { BOOL = true }
    Required      = { BOOL = true }
    ValuePattern  = { S = "^[a-zA-Z0-9._%+-]+@company\\.com$" }
    AccountIds    = { SS = ["*"] }
  })
}
```

### Example 3: Optional Cost Center Tag (Account-specific)

```hcl
# Store rule in DynamoDB
resource "aws_dynamodb_table_item" "cost_center_rule" {
  table_name = aws_dynamodb_table.tagging_rules.name
  item = jsonencode({
    ResourceType = { S = "AWS::RDS::DBInstance" }
    Tag          = { S = "CostCenter" }
    Enabled      = { BOOL = true }
    Required     = { BOOL = false }  # Optional tag
    Values       = { SS = ["CC-001", "CC-002", "CC-003"] }
    AccountIds   = { SS = ["123456789012", "210987654321"] }  # Specific accounts
  })
}
```

### Example 4: Full Module Configuration

```hcl
# DynamoDB table for rules
resource "aws_dynamodb_table" "tagging_rules" {
  name           = "tagging-compliance-rules"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "ResourceType"
  
  attribute {
    name = "ResourceType"
    type = "S"
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Deploy the config module
module "config_tagging_compliance" {
  source = "./modules/config"

  dynamodb_table_arn = aws_dynamodb_table.tagging_rules.arn

  lambda_name        = "tagging-compliance"
  lambda_description = "Evaluates resource tagging compliance via AWS Config"
  lambda_log_level   = "DEBUG"

  config_name                    = "resource-tagging-compliance"
  config_max_execution_frequency = "Six_Hours"
  config_resource_types          = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::Lambda::Function"]

  cloudwatch_logs_retention_in_days = 14
  cloudwatch_logs_kms_key_id        = aws_kms_key.logs.id

  tags = {
    Environment = "production"
    Team        = "platform-engineering"
  }
}

# Output compliance status
output "config_rule_arn" {
  value = module.config_tagging_compliance.config_rule_arn
}

output "lambda_function_arn" {
  value = module.config_tagging_compliance.lambda_function_arn
}
```

## Compliance Evaluation Logic

The Lambda function evaluates resources against rules using the following logic:

1. **Rule Matching**: Find all enabled rules matching the resource type and account
2. **Tag Presence Check**: For required tags, verify the tag exists on the resource
3. **Value Validation**: If values are specified, verify the tag value is in the permitted list
4. **Pattern Matching**: If a regex pattern is specified, verify the tag value matches the pattern
5. **Result**: Mark resource as:
   - **COMPLIANT**: All required tags present with valid values
   - **NON_COMPLIANT**: Missing required tags or invalid values
   - **NOT_APPLICABLE**: No matching rules for the resource

## Monitoring and Troubleshooting

### CloudWatch Logs
The Lambda function outputs structured JSON logs. Query them using CloudWatch Logs Insights:

```
fields @timestamp, @message, compliance_type, resource_id
| filter action = "lambda_handler"
| stats count() by compliance_type
```

### AWS Config Console
View compliance status directly in the AWS Config console:
- Navigate to **Config Rules** → **tagging-compliance** rule
- See non-compliant resources and compliance timeline
- Remediate resources or update rules as needed

### Common Issues

- **No matching rules found**: Verify the rule `ResourceType` pattern matches your resources
- **Lambda timeout**: Increase `lambda_timeout` if evaluating many tags
- **Permission errors**: Verify Lambda role has access to both DynamoDB and Config

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dynamodb_table_arn"></a> [dynamodb\_table\_arn](#input\_dynamodb\_table\_arn) | The ARN of the DynamoDB table to store tags for AWS resources. | `string` | n/a | yes |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_config_max_execution_frequency"></a> [config\_max\_execution\_frequency](#input\_config\_max\_execution\_frequency) | The maximum frequency with which the AWS Config rule should be evaluated. Valid values are One\_Hour, Three\_Hours, Six\_Hours, Twelve\_Hours, or TwentyFour\_Hours. | `string` | `"TwentyFour_Hours"` | no |
| <a name="input_config_name"></a> [config\_name](#input\_config\_name) | The name of the AWS Config rule | `string` | `"tagging-compliance"` | no |
| <a name="input_config_resource_types"></a> [config\_resource\_types](#input\_config\_resource\_types) | List of AWS resource types to evaluate | `list(string)` | <pre>[<br/>  "*"<br/>]</pre> | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function to handle AWS Organization account movements. | `string` | `"Handles AWS Organization account movements for tagging compliance."` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL. | `string` | `"INFO"` | no |
| <a name="input_lambda_name"></a> [lambda\_name](#input\_lambda\_name) | The name of the Lambda function to handle AWS Organization account movements. | `string` | `"tagging-compliance-handler"` | no |
| <a name="input_lambda_role_name"></a> [lambda\_role\_name](#input\_lambda\_role\_name) | The name of the IAM role to be created for the Lambda function. | `string` | `"tagging-compliance-lambda"` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | The runtime environment for the Lambda function. | `string` | `"python3.12"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | The timeout for the Lambda function in seconds. | `number` | `30` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the Lambda function. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_config_arn"></a> [config\_arn](#output\_config\_arn) | The ARN of the AWS Config rule for tagging compliance. |
| <a name="output_lambda_arn"></a> [lambda\_arn](#output\_lambda\_arn) | The ARN of the Lambda function for tagging compliance. |
<!-- END_TF_DOCS -->