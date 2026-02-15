# AWS Config Conformance Pack Module

This module creates an AWS Config Conformance Pack for tagging compliance that can be deployed organization-wide or to individual accounts. The conformance pack template is stored in S3 and references the Lambda-based custom Config rule for evaluating resource tagging compliance.

## Features

- **S3-based Distribution**: Stores conformance pack template in S3 for version control and distribution
- **Organization-Wide Deployment**: Deploy to all accounts in an AWS Organization from the management account
- **Account-Level Deployment**: Deploy to individual accounts as needed
- **Account Exclusions**: Exclude specific accounts from organization-wide deployment
- **Parameterized Templates**: Support for input parameters to customize deployment
- **Secure by Default**: S3 bucket with encryption, versioning, and public access blocking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Management Account                          │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  S3 Bucket                                            │  │
│  │  • conformance-pack.yaml (template)                  │  │
│  │  • Versioning enabled                                │  │
│  │  • Encrypted with KMS                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                   │
│  ┌──────────────────────▼───────────────────────────────┐  │
│  │  AWS Config Organization Conformance Pack             │  │
│  │  • Deploys to all accounts                           │  │
│  │  • Excludes specified accounts                       │  │
│  │  • References Lambda function                        │  │
│  │  • References DynamoDB table                         │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
       ┌──────────────────┼──────────────────┐
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Account A  │    │  Account B  │    │  Account C  │
│             │    │             │    │             │
│ Config Rule │    │ Config Rule │    │ Config Rule │
│      ↓      │    │      ↓      │    │      ↓      │
│   Lambda    │    │   Lambda    │    │   Lambda    │
│             │    │             │    │             │
│  Evaluates  │    │  Evaluates  │    │  Evaluates  │
│  Resources  │    │  Resources  │    │  Resources  │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Usage

### Organization-Wide Deployment

Deploy the conformance pack to all accounts in your AWS Organization:

```hcl
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "org-tagging-compliance"
  s3_bucket_name        = "my-org-conformance-packs-123456789012"
  
  # Enable organization-wide deployment
  deploy_organization_wide = true
  excluded_accounts        = ["111111111111"]  # Exclude sandbox accounts

  # Reference the Lambda function and DynamoDB table
  lambda_function_arn = "arn:aws:lambda:us-east-1:999999999999:function:tagging-compliance-evaluator"
  dynamodb_table_arn  = "arn:aws:dynamodb:us-east-1:999999999999:table/tagging-compliance-rules"

  # Specify resource types to evaluate
  resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function"
  ]

  max_execution_frequency = "Six_Hours"

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
    Purpose     = "tagging-compliance"
  }
}
```

### Account-Level Deployment

Deploy the conformance pack to a single account:

```hcl
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "tagging-compliance"
  s3_bucket_name        = "tagging-conformance-pack-123456789012"
  
  # Account-level deployment
  deploy_organization_wide = false

  lambda_function_arn = module.tagging_config.lambda_function_arn
  dynamodb_table_arn  = data.aws_dynamodb_table.compliance_rules.arn

  resource_types = ["AWS::*"]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Complete Organization Example

Complete setup with central rules, per-account Lambda, and organization conformance pack:

```hcl
# Management Account - Central DynamoDB table and conformance pack
module "tagging_central" {
  source = "appvia/tagging/aws"

  dynamodb_table_name = "org-tagging-compliance"
  organization_id     = data.aws_organizations_organization.current.id

  rules = [
    {
      RuleId       = "global-environment-tag"
      ResourceType = "AWS::*"
      Tag          = "Environment"
      Required     = true
      Values       = ["production", "staging", "development"]
      AccountIds   = ["*"]
      Enabled      = true
    }
  ]
}

# Deploy Lambda to management account (or shared services)
module "tagging_lambda" {
  source = "appvia/tagging/aws//modules/config"

  dynamodb_table_arn    = module.tagging_central.dynamodb_arn
  config_resource_types = ["AWS::*"]
  lambda_name           = "org-tagging-evaluator"
  config_name           = "org-tagging-compliance"
}

# Create organization conformance pack
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance-pack"
  s3_bucket_name           = "org-conformance-packs-${data.aws_caller_identity.current.account_id}"
  deploy_organization_wide = true

  lambda_function_arn = module.tagging_lambda.lambda_function_arn
  dynamodb_table_arn  = module.tagging_central.dynamodb_arn

  resource_types          = ["AWS::*"]
  max_execution_frequency = "TwentyFour_Hours"

  # Exclude test/sandbox accounts
  excluded_accounts = [
    "111111111111",
    "222222222222"
  ]

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
  }
}
```

### With Custom Parameters

Pass custom parameters to the conformance pack:

```hcl
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "tagging-compliance"
  s3_bucket_name           = "conformance-packs"
  deploy_organization_wide = true

  lambda_function_arn = var.lambda_function_arn
  dynamodb_table_arn  = var.dynamodb_table_arn

  # Custom parameters
  input_parameters = {
    Environment = "production"
    Severity    = "high"
  }

  # Enable S3 encryption
  s3_kms_key_id = aws_kms_key.conformance_packs.id
}
```

## Conformance Pack Template

The module generates a CloudFormation-compatible conformance pack template that includes:

- AWS Config custom rule referencing your Lambda function
- Scope configuration for resource types
- Event triggers for configuration changes and scheduled evaluations
- Input parameters for DynamoDB table ARN

The template is stored in S3 and can be versioned for change tracking.

## Deployment Strategies

### Gradual Rollout

Deploy to specific accounts first, then expand:

```hcl
# Phase 1: Deploy to dev/test accounts
module "tagging_pack_phase1" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "tagging-compliance-phase1"
  s3_bucket_name           = "conformance-packs"
  deploy_organization_wide = true

  excluded_accounts = [
    # Exclude production accounts initially
    "111111111111",  # prod-account-1
    "222222222222",  # prod-account-2
  ]

  lambda_function_arn = var.lambda_function_arn
  dynamodb_table_arn  = var.dynamodb_table_arn
}

# Phase 2: Deploy to all accounts (remove exclusions)
# Update excluded_accounts = [] after validation
```

### Environment-Based Deployment

Deploy different packs for different environments:

```hcl
# Production conformance pack
module "tagging_pack_prod" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "tagging-compliance-prod"
  s3_bucket_name        = "conformance-packs-prod"
  
  deploy_organization_wide = true
  excluded_accounts        = var.non_prod_accounts

  resource_types          = ["AWS::*"]
  max_execution_frequency = "Six_Hours"  # More frequent

  lambda_function_arn = var.lambda_function_arn
  dynamodb_table_arn  = var.dynamodb_table_arn
}

# Development conformance pack
module "tagging_pack_dev" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "tagging-compliance-dev"
  s3_bucket_name        = "conformance-packs-dev"
  
  deploy_organization_wide = true
  excluded_accounts        = var.prod_accounts

  resource_types          = ["AWS::*"]
  max_execution_frequency = "TwentyFour_Hours"  # Less frequent

  lambda_function_arn = var.lambda_function_arn
  dynamodb_table_arn  = var.dynamodb_table_arn
}
```

## Benefits of Conformance Packs

### Centralized Management
- Single source of truth for compliance configuration
- Version-controlled template in S3
- Easy to update and redeploy

### Organization-Wide Enforcement
- Automatically applies to new accounts
- Consistent compliance posture across all accounts
- Simplified compliance reporting

### Reduced Operational Overhead
- Deploy once, applies everywhere
- No need to manage Config rules in each account
- Automatic rollback on failures

### Compliance Reporting
- Organization-wide compliance dashboard
- Aggregated compliance status
- Account-level drill-down

## Monitoring

### View Conformance Pack Status

```bash
# Organization conformance pack status
aws configservice describe-organization-conformance-pack-statuses

# Account-level conformance pack status
aws configservice describe-conformance-pack-status
```

### View Compliance Results

```bash
# Organization-wide compliance summary
aws configservice get-organization-conformance-pack-detailed-status \
  --organization-conformance-pack-name tagging-compliance-pack

# Account compliance details
aws configservice describe-conformance-pack-compliance \
  --conformance-pack-name tagging-compliance
```

## Prerequisites

- AWS Config must be enabled in target accounts
- AWS Organizations (for organization-wide deployment)
- Lambda function must be deployed and accessible
- DynamoDB table must have organization-wide read access
- IAM permissions for Config to invoke Lambda function

## Limitations

- Organization conformance packs can only be deployed from the management account
- Maximum 50 conformance packs per organization
- Maximum 200 Config rules per account
- Template size limit: 51,200 bytes
- S3 bucket must be in the same region as the conformance pack

## Best Practices

1. **Version Your Templates**: Enable S3 versioning to track changes
2. **Encrypt S3 Bucket**: Use KMS encryption for sensitive configurations
3. **Test Before Organization Rollout**: Deploy to test accounts first
4. **Monitor Deployment Status**: Check for failed deployments
5. **Use Descriptive Names**: Make conformance pack names meaningful
6. **Document Exclusions**: Clearly document why accounts are excluded
7. **Regular Reviews**: Periodically review and update conformance packs

## Troubleshooting

### Deployment Failures

If conformance pack deployment fails:

1. Check Lambda function exists and is accessible
2. Verify DynamoDB table ARN is correct
3. Ensure AWS Config is enabled in target accounts
4. Review IAM permissions for Config service
5. Check CloudFormation stack events for errors

### Compliance Evaluation Issues

If resources aren't being evaluated:

1. Verify Lambda function has correct permissions
2. Check DynamoDB table access from target accounts
3. Review Lambda function logs in CloudWatch
4. Ensure resource types match what you're evaluating
5. Verify Config recorder is active

## Security Considerations

- **S3 Bucket Access**: Bucket is private by default with public access blocked
- **Encryption**: Enable KMS encryption for sensitive data
- **Cross-Account Access**: DynamoDB table requires organization-wide read policy
- **Lambda Permissions**: Function needs Config and DynamoDB access
- **Least Privilege**: Apply minimal permissions for conformance pack operations

## Update Documentation

The `terraform-docs` utility is used to generate documentation. Follow these steps to update:

1. Make changes to the `.terraform-docs.yml` file
2. Fetch the `terraform-docs` binary (https://terraform-docs.io/user-guide/installation/)
3. Run `terraform-docs markdown table --output-file ${PWD}/README.md --output-mode inject .`

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_compliance_rule_table_arn"></a> [compliance\_rule\_table\_arn](#input\_compliance\_rule\_table\_arn) | ARN of the DynamoDB table containing compliance rules | `string` | n/a | yes |
| <a name="input_s3_bucket_name"></a> [s3\_bucket\_name](#input\_s3\_bucket\_name) | Name of the S3 bucket to store the conformance pack template | `string` | n/a | yes |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | KMS key ID for encrypting CloudWatch Logs (optional) | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | Log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | Number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_config_rule_name"></a> [config\_rule\_name](#input\_config\_rule\_name) | Name of the AWS Config rule within the conformance pack | `string` | `"tagging-compliance"` | no |
| <a name="input_conformance_pack_name"></a> [conformance\_pack\_name](#input\_conformance\_pack\_name) | Name of the AWS Config Conformance Pack | `string` | `"tagging-compliance"` | no |
| <a name="input_deploy_organization_wide"></a> [deploy\_organization\_wide](#input\_deploy\_organization\_wide) | Whether to deploy the conformance pack organization-wide (requires Organizations management account) | `bool` | `false` | no |
| <a name="input_excluded_accounts"></a> [excluded\_accounts](#input\_excluded\_accounts) | List of AWS account IDs to exclude from organization conformance pack deployment | `list(string)` | `[]` | no |
| <a name="input_input_parameters"></a> [input\_parameters](#input\_input\_parameters) | Map of input parameters to pass to the conformance pack | `map(string)` | `{}` | no |
| <a name="input_lambda_function_arn"></a> [lambda\_function\_arn](#input\_lambda\_function\_arn) | ARN of the Lambda function that evaluates compliance | `string` | `null` | no |
| <a name="input_max_execution_frequency"></a> [max\_execution\_frequency](#input\_max\_execution\_frequency) | Maximum frequency for Config rule evaluation | `string` | `"TwentyFour_Hours"` | no |
| <a name="input_pack_description"></a> [pack\_description](#input\_pack\_description) | Description of the conformance pack | `string` | `"AWS Config Conformance Pack for validating resource tagging compliance"` | no |
| <a name="input_resource_types"></a> [resource\_types](#input\_resource\_types) | List of AWS resource types to evaluate (e.g., AWS::EC2::Instance) | `list(string)` | <pre>[<br/>  "AWS::*"<br/>]</pre> | no |
| <a name="input_s3_enable_versioning"></a> [s3\_enable\_versioning](#input\_s3\_enable\_versioning) | Enable versioning for the S3 bucket | `bool` | `true` | no |
| <a name="input_s3_kms_key_id"></a> [s3\_kms\_key\_id](#input\_s3\_kms\_key\_id) | KMS key ID for S3 bucket encryption (optional) | `string` | `null` | no |
| <a name="input_s3_template_key"></a> [s3\_template\_key](#input\_s3\_template\_key) | S3 object key for the conformance pack template | `string` | `"conformance-packs/tagging-compliance.yaml"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_conformance_pack_arn"></a> [conformance\_pack\_arn](#output\_conformance\_pack\_arn) | ARN of the conformance pack |
| <a name="output_conformance_pack_id"></a> [conformance\_pack\_id](#output\_conformance\_pack\_id) | ID of the conformance pack |
| <a name="output_conformance_pack_name"></a> [conformance\_pack\_name](#output\_conformance\_pack\_name) | Name of the conformance pack |
| <a name="output_s3_bucket_arn"></a> [s3\_bucket\_arn](#output\_s3\_bucket\_arn) | ARN of the S3 bucket storing the conformance pack template |
| <a name="output_s3_bucket_name"></a> [s3\_bucket\_name](#output\_s3\_bucket\_name) | Name of the S3 bucket storing the conformance pack template |
| <a name="output_s3_template_uri"></a> [s3\_template\_uri](#output\_s3\_template\_uri) | S3 URI of the conformance pack template |
<!-- END_TF_DOCS -->
