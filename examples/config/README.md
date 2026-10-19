# Config Module Example

## Description

This example demonstrates how to deploy the AWS Config module to enforce tagging compliance in an AWS account. It creates an AWS Config custom rule that evaluates resources against a YAML tagging policy stored in a central S3 bucket.

The config module integrates with the validation module (Lambda function) to perform real-time compliance evaluation whenever resources are created or modified.

## What This Example Creates

1. **AWS Config Custom Rule**: Named `tagging-compliance` that evaluates S3 buckets
2. **Lambda Function**: Python-based evaluator (via validation module) that reads YAML policy from S3
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
│  │  • Loads YAML policy from S3                             │  │
│  │  • Evaluates resource tags                               │  │
│  │  • Returns compliance status                             │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-Account Read (HTTPS)                │
│                      ▼                                            │
│                [S3 Bucket: policy.yaml, mappings.yaml]           │
│                (Management Account)                              │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration Example

```hcl
module "config" {
  source = "../../modules/config"

  # Reference central S3 policy bucket (typically in management account)
  policy_bucket_name = "tagging-compliance-config"
  policy_bucket_arn  = "arn:aws:s3:::tagging-compliance-config"
  policy_key         = "policy.yaml"
  policy_version     = module.tagging.policy_version
  mappings_key       = "mappings.yaml"
  mappings_version   = module.tagging.mappings_version
  accounts_key       = "accounts.yaml"
  
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
- **S3 Bucket with Policy**: Central S3 bucket with policy.yaml and mappings.yaml must exist (created via root module)
- Permissions to:
  - Create Lambda functions and IAM roles
  - Create AWS Config rules
  - Create CloudWatch log groups
  - Read from the S3 bucket (cross-account if in different account)
  - kms:Decrypt if the S3 bucket is encrypted with a customer-managed KMS key

## When to Use This Example

Use this config module example when:
- You want to enforce tagging compliance in a specific AWS account
- You have a central S3 bucket with a YAML tagging policy already created
- You need AWS Config to continuously evaluate resource compliance
- You want real-time compliance reporting in the AWS Config console

## Module Configuration Options

### Minimal Configuration

```hcl
module "config" {
  source = "../../modules/config"

  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_version     = "abc123..."
  mappings_version   = "def456..."
  config_resource_types = ["AWS::S3::Bucket"]
}
```

### Full Configuration with All Options

```hcl
module "config" {
  source = "../../modules/config"

  # S3 bucket with tagging policy (typically in management account)
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."  # From root module output
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."  # From root module output
  accounts_key       = "accounts.yaml"

  # Lambda configuration (via validation module)
  lambda_name        = "tagging-compliance-evaluator"
  lambda_description = "Evaluates resource tagging compliance"
  lambda_runtime     = "python3.14"
  lambda_timeout     = 60
  lambda_memory_size = 256
  lambda_log_level   = "INFO"

  # Policy caching configuration
  rules_cache_enabled     = true
  rules_cache_ttl_seconds = 300

  # AWS Config rule settings
  config_name                  = "tagging-compliance"
  maximum_execution_frequency  = "Six_Hours"
  periodic_evaluation_enabled  = true
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

  # KMS key for encrypted S3 bucket (if applicable)
  kms_key_arn = null

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

### S3 Access Denied

Ensure the Lambda IAM role has S3 read permissions for the policy bucket and that the bucket policy allows cross-account access (if applicable). If the bucket is encrypted with KMS, verify the Lambda role has kms:Decrypt permission on the key.

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will delete the Lambda function and AWS Config rule. The S3 bucket with the tagging policy is not affected.

<!-- BEGIN_TF_DOCS -->
## Providers

No providers.

## Inputs

No inputs.

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_config_rule_arn"></a> [config\_rule\_arn](#output\_config\_rule\_arn) | The ARN of the AWS Config rule created for tagging compliance. |
<!-- END_TF_DOCS -->
