# Config Module Example

## Description

This example demonstrates how to deploy the AWS Config module to enforce tagging compliance in an AWS account. It creates an AWS Config custom rule that evaluates resources against tagging standards stored in a central DynamoDB table.

The config module integrates with the validation module (Lambda function) to perform real-time compliance evaluation whenever resources are created or modified.

## What This Example Creates

1. **AWS Config Custom Rule**: Named `tagging-compliance` that evaluates S3 buckets
2. **Lambda Function**: Python-based evaluator (via validation module) that reads rules from DynamoDB
3. **IAM Permissions**: Allows AWS Config to invoke the Lambda function
4. **CloudWatch Logs**: Structured JSON logging for compliance evaluations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    This Account                                  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  AWS Config Custom Rule                                   │  │
│  │  Name: tagging-compliance                                │  │
│  │  Scope: AWS::S3::Bucket                                  │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Triggers                                  │
│                      ▼                                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Lambda Function                                          │  │
│  │  • Reads rules from DynamoDB                             │  │
│  │  • Evaluates resource tags                               │  │
│  │  • Returns compliance status                             │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-Account Read                        │
│                      ▼                                            │
│                [Central DynamoDB Table]                          │
│                (Management Account)                              │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration Example

```hcl
module "config" {
  source = "../../modules/config"

  # Reference central DynamoDB table (typically in management account)
  dynamodb_table_arn = "arn:aws:dynamodb:eu-west-1:123456789012:table/tagging-compliance"
  
  # AWS Config rule configuration
  config_name           = "tagging-compliance"
  config_resource_types = ["AWS::S3::Bucket"]  # Evaluate S3 buckets only
}
```

## Usage

```bash
# Initialize Terraform
terraform init

# Review the planned changes
terraform plan

# Apply the configuration
terraform apply
```

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate credentials
- **DynamoDB Table**: Central tagging rules table must exist (created via root module or compliance module)
- Permissions to:
  - Create Lambda functions and IAM roles
  - Create AWS Config rules
  - Create CloudWatch log groups
  - Read from the DynamoDB table (cross-account if in different account)

## When to Use This Example

Use this config module example when:
- You want to enforce tagging compliance in a specific AWS account
- You have a central DynamoDB table with tagging rules already created
- You need AWS Config to continuously evaluate resource compliance
- You want real-time compliance reporting in the AWS Config console

## Module Configuration Options

### Minimal Configuration

```hcl
module "config" {
  source = "../../modules/config"

  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/tagging-compliance"
  config_name        = "tagging-compliance"
}
```

### Full Configuration with All Options

```hcl
module "config" {
  source = "../../modules/config"

  # DynamoDB table with tagging rules (typically in management account)
  dynamodb_table_arn = "arn:aws:dynamodb:us-east-1:999999999999:table/tagging-compliance"

  # Lambda configuration (via validation module)
  lambda_name        = "tagging-compliance-evaluator"
  lambda_description = "Evaluates resource tagging compliance"
  lambda_timeout     = 60
  lambda_memory_size = 256
  lambda_log_level   = "INFO"

  # AWS Config rule settings
  config_name                    = "tagging-compliance"
  config_description             = "Evaluates tagging compliance for AWS resources"
  config_max_execution_frequency = "Six_Hours"
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function"
  ]

  # CloudWatch Logs
  cloudwatch_logs_retention_in_days = 14
  cloudwatch_logs_kms_key_id        = null  # Optional KMS encryption

  # Cross-account support (for organization-wide Lambda)
  organization_id          = "o-123456789"  # Allow all org accounts
  allowed_source_accounts  = []             # Or specific accounts

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

## Resource Types to Evaluate

Common resource types for tagging compliance:

- `AWS::EC2::Instance` - EC2 instances
- `AWS::EC2::Volume` - EBS volumes
- `AWS::EC2::SecurityGroup` - Security groups
- `AWS::S3::Bucket` - S3 buckets
- `AWS::RDS::DBInstance` - RDS databases
- `AWS::RDS::DBCluster` - RDS clusters
- `AWS::Lambda::Function` - Lambda functions
- `AWS::DynamoDB::Table` - DynamoDB tables
- `AWS::ECS::Cluster` - ECS clusters
- `AWS::ECS::Service` - ECS services
- `AWS::*` - All supported resource types

## Next Steps

After deploying this example:

1. **Create an S3 Bucket**: Test the compliance evaluation
   ```bash
   aws s3api create-bucket --bucket test-bucket-$(date +%s)
   ```

2. **View Compliance Status**: Check the AWS Config console
   - Navigate to **AWS Config** → **Rules** → `tagging-compliance`
   - View compliant and non-compliant resources

3. **Check Lambda Logs**: View evaluation details
   ```bash
   aws logs tail /aws/lambda/tagging-compliance-evaluator --follow
   ```

4. **Query Compliance Results**:
   ```bash
   aws configservice describe-compliance-by-config-rule \
     --config-rule-names tagging-compliance
   ```

## Viewing Compliance Results

### AWS Console

1. Navigate to **AWS Config** → **Rules**
2. Click on **tagging-compliance** rule
3. View resources and their compliance status
4. Click individual resources to see evaluation details

### AWS CLI

```bash
# Get non-compliant resources
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name tagging-compliance \
  --compliance-types NON_COMPLIANT

# View Lambda execution logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/tagging-compliance-evaluator \
  --filter-pattern "compliance_type"
```

## Troubleshooting

### Resource Not Evaluated

Verify the resource type is in the Config rule scope:
```bash
aws configservice describe-config-rules --config-rule-names tagging-compliance
```

### Lambda Function Errors

Check CloudWatch Logs for execution errors:
```bash
aws logs tail /aws/lambda/tagging-compliance-evaluator --follow
```

### DynamoDB Access Denied

Ensure the Lambda IAM role has read permissions for the DynamoDB table and that the table's resource policy allows cross-account access (if applicable).

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will delete the DynamoDB table and all rules.

<!-- BEGIN_TF_DOCS -->
## Providers

No providers.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_compliance_rule_table_arn"></a> [compliance\_rule\_table\_arn](#input\_compliance\_rule\_table\_arn) | The ARN of the DynamoDB table to store tags for AWS resources. | `string` | n/a | yes |
| <a name="input_organizations_table_arn"></a> [organizations\_table\_arn](#input\_organizations\_table\_arn) | The ARN of the DynamoDB table to store organization metadata. | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_config_rule_arn"></a> [config\_rule\_arn](#output\_config\_rule\_arn) | The ARN of the AWS Config rule created for tagging compliance. |
<!-- END_TF_DOCS -->
