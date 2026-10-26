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
┌───────────────────────────────────────────────────────────────┐
│                  Management Account                            │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Policy Bucket (S3)                                     │  │
│  │  • policy.yaml (tagging rules)                         │  │
│  │  • mappings.yaml (resource type mappings)              │  │
│  │  • accounts.yaml (account inventory)                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Pack Bucket (S3)                                       │  │
│  │  • conformance-pack.yaml (CloudFormation template)     │  │
│  │  • Versioning enabled                                   │  │
│  │  • Encrypted (KMS or AES256)                           │  │
│  └────────────────────────────────────────────────────────┘  │
│                          │                                     │
│  ┌──────────────────────▼─────────────────────────────────┐  │
│  │  AWS Config Organization Conformance Pack               │  │
│  │  • Deploys to all accounts                             │  │
│  │  • Excludes specified accounts                         │  │
│  │  • Parameters: PolicyVersion, MappingsVersion,         │  │
│  │    InventoryVersion (triggers re-evaluation on change) │  │
│  └────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
                          │
       ┌──────────────────┼──────────────────┐
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Account A  │    │  Account B  │    │  Account C  │
│             │    │             │    │             │
│ Config Rule │    │ Config Rule │    │ Config Rule │
│      ↓      │    │      ↓      │    │      ↓      │
│   Lambda ───┼────┼─> Reads ────┼────┼───┐         │
│             │    │             │    │   │         │
│  Evaluates  │    │  Evaluates  │    │   │         │
│  Resources  │    │  Resources  │    │   │         │
└─────────────┘    └─────────────┘    │   │         │
                                       │   │         │
                                       ▼   ▼         │
                            ┌──────────────────────┐ │
                            │  Policy Bucket (S3)  │ │
                            │  Cross-account read  │◀┘
                            └──────────────────────┘
```

## Usage

### Organization-Wide Deployment

Deploy the conformance pack to all accounts in your AWS Organization:

```hcl
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "org-tagging-compliance"
  s3_bucket_name        = "my-org-conformance-packs-123456789012"
  
  # Policy, mappings, and inventory configuration
  policy_bucket_name = "org-tagging-policy"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-policy"
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  
  # Version hashes from root module outputs
  policy_version   = "abc123..."
  mappings_version = "def456..."
  
  # Enable organization-wide deployment
  deploy_organization_wide = true
  excluded_accounts        = ["111111111111"]  # Exclude sandbox accounts

  # Optional: reference existing Lambda (otherwise module creates one)
  lambda_function_arn = "arn:aws:lambda:us-east-1:999999999999:function:tagging-compliance-evaluator"
  
  # Optional: KMS key for policy bucket encryption
  kms_key_arn = "arn:aws:kms:us-east-1:999999999999:key/..."

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
  
  # Policy and mappings configuration
  policy_bucket_name = "org-tagging-policy"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-policy"
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = null  # No inventory for account-level deployment
  
  # Version hashes
  policy_version   = var.policy_version
  mappings_version = var.mappings_version
  
  # Account-level deployment
  deploy_organization_wide = false

  # Module creates a Lambda function automatically
  lambda_function_arn = null

  resource_types = ["AWS::*"]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Complete Organization Example

Complete setup with policy in S3, Lambda, and organization conformance pack:

```hcl
# Management Account - Central policy bucket
module "tagging_central" {
  source = "appvia/tagging/aws"

  s3_bucket_name  = "org-tagging-policy"
  organization_id = data.aws_organizations_organization.current.id

  # Policy is written to S3 as policy.yaml
  policy = file("${path.module}/tagging-policy.yaml")
  
  # Mappings are written to S3 as mappings.yaml
  mappings = file("${path.module}/mappings.yaml")
}

# Deploy Lambda to management account (or shared services)
module "tagging_lambda" {
  source = "appvia/tagging/aws//modules/validation"

  policy_bucket_name = module.tagging_central.bucket_name
  policy_bucket_arn  = module.tagging_central.bucket_arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  
  lambda_name      = "org-tagging-evaluator"
  lambda_role_name = "org-tagging-evaluator"
}

# Create organization conformance pack
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance-pack"
  s3_bucket_name           = "org-conformance-packs-${data.aws_caller_identity.current.account_id}"
  deploy_organization_wide = true

  # Policy configuration
  policy_bucket_name = module.tagging_central.bucket_name
  policy_bucket_arn  = module.tagging_central.bucket_arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  
  # Version hashes trigger re-evaluation
  policy_version   = module.tagging_central.policy_version
  mappings_version = module.tagging_central.mappings_version

  # Use the shared Lambda
  lambda_function_arn = module.tagging_lambda.lambda_arn

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

### Bootstrap: First Apply with Policy Bucket Created

On the first apply when the policy bucket is created in the same configuration, pass `inventory_version = "none"` to avoid reading the (not yet existing) inventory object at plan time:

```hcl
module "tagging_conformance_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "tagging-compliance"
  s3_bucket_name        = "conformance-packs"
  
  policy_bucket_name = aws_s3_bucket.policy.id
  policy_bucket_arn  = aws_s3_bucket.policy.arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  
  policy_version   = "abc123..."
  mappings_version = "def456..."
  
  # Bootstrap: pin inventory version to "none" on first apply
  inventory_version = "none"  # Remove this after first apply
  
  deploy_organization_wide = true
  lambda_function_arn      = var.lambda_function_arn

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

After the first apply completes, remove the `inventory_version` line so the module reads the actual content-sha256 from the inventory object metadata.

## Conformance Pack Template

The module generates a CloudFormation-compatible conformance pack template that includes:

- AWS Config custom rule referencing your Lambda function
- Scope configuration for resource types (e.g., `AWS::EC2::Instance`, `AWS::S3::Bucket`)
- Event triggers for configuration changes and scheduled evaluations
- Pack parameters `PolicyVersion`, `MappingsVersion` and `InventoryVersion` (type String, default `none`), passed to the Config rule's `InputParameters`

The template is stored in S3 and can be versioned for change tracking.

The version parameters carry content hashes only; the Lambda reads the policy location from its environment variables. Changing any of them updates the Config rule's input parameters and makes AWS Config re-evaluate every in-scope resource across all accounts. The module sets `PolicyVersion` and `MappingsVersion` from the `policy_version` and `mappings_version` inputs (typically from the root module outputs). `InventoryVersion` is read from the S3 object's `content-sha256` metadata (or set to `none` when no inventory is configured). The organizations Lambda re-puts the pack with a new `InventoryVersion` when the inventory changes, triggering automatic re-evaluation.

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

  policy_bucket_name = var.policy_bucket_name
  policy_bucket_arn  = var.policy_bucket_arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  policy_version     = var.policy_version
  mappings_version   = var.mappings_version

  excluded_accounts = [
    # Exclude production accounts initially
    "111111111111",  # prod-account-1
    "222222222222",  # prod-account-2
  ]

  lambda_function_arn = var.lambda_function_arn
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

  policy_bucket_name = var.policy_bucket_name
  policy_bucket_arn  = var.policy_bucket_arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  policy_version     = var.policy_version
  mappings_version   = var.mappings_version

  resource_types          = ["AWS::*"]
  max_execution_frequency = "Six_Hours"  # More frequent

  lambda_function_arn = var.lambda_function_arn
}

# Development conformance pack
module "tagging_pack_dev" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name = "tagging-compliance-dev"
  s3_bucket_name        = "conformance-packs-dev"
  
  deploy_organization_wide = true
  excluded_accounts        = var.prod_accounts

  policy_bucket_name = var.policy_bucket_name
  policy_bucket_arn  = var.policy_bucket_arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"
  policy_version     = var.policy_version
  mappings_version   = var.mappings_version

  resource_types          = ["AWS::*"]
  max_execution_frequency = "TwentyFour_Hours"  # Less frequent

  lambda_function_arn = var.lambda_function_arn
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
- Lambda function must be deployed and accessible from member accounts
- S3 bucket with tagging policy, mappings, and inventory must be accessible with organization-wide read permissions
- IAM permissions for Config to invoke Lambda function
- Lambda must have S3 read access to the policy bucket (cross-account if in different account)
- If policy bucket is encrypted with KMS, Lambda needs `kms:Decrypt` permission

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

1. Check Lambda function exists and is accessible from member accounts
2. Verify policy bucket exists and policy/mappings objects are present
3. Ensure AWS Config is enabled in target accounts
4. Review IAM permissions for Config service to invoke Lambda
5. Check CloudFormation stack events for errors in the Config console
6. Verify `policy_version` and `mappings_version` are set correctly

### Compliance Evaluation Issues

If resources aren't being evaluated:

1. Verify Lambda function has S3 read access to the policy bucket
2. Check Lambda has `kms:Decrypt` permission if policy bucket is encrypted
3. Review Lambda function logs in CloudWatch for policy loading errors
4. Ensure resource types in `resource_types` match what you're evaluating
5. Verify Config recorder is active in member accounts
6. Check that the resource type is mapped in `mappings.yaml`

### Re-evaluation Not Triggering

If changing the policy doesn't trigger re-evaluation:

1. Verify `policy_version` input changes when the policy changes
2. Check the conformance pack input parameters in the Config console
3. For inventory changes, verify the organizations Lambda is updating the pack's `InventoryVersion`
4. Review Terraform plan to ensure the pack resource is being updated

## Security Considerations

- **S3 Bucket Access**: Both pack bucket and policy bucket are private by default with public access blocked
- **Encryption**: Enable KMS encryption for sensitive data (both buckets support optional KMS encryption)
- **Cross-Account Access**: Policy bucket requires organization-wide read policy for Lambda in member accounts
- **Lambda Permissions**: Function needs Config, S3, and KMS (if encrypted) access
- **KMS Key Policy**: If using KMS, the key policy must grant `kms:Decrypt` to the Lambda role and organization principals
- **Least Privilege**: Apply minimal permissions for conformance pack operations

## Update Documentation

The `terraform-docs` utility is used to generate documentation. Follow these steps to update:

1. Make changes to the `.terraform-docs.yml` file
2. Fetch the `terraform-docs` binary (https://terraform-docs.io/user-guide/installation/)
3. Run `terraform-docs markdown table --output-file ${PWD}/README.md --output-mode inject .`

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_mappings_version"></a> [mappings\_version](#input\_mappings\_version) | A hash of the mappings content (root module output mappings\_version), passed as the MappingsVersion pack parameter to force re-evaluation on change. | `string` | n/a | yes |
| <a name="input_policy_version"></a> [policy\_version](#input\_policy\_version) | A hash of the tagging policy content (root module output policy\_version), passed as the PolicyVersion pack parameter to force re-evaluation on change. | `string` | n/a | yes |
| <a name="input_s3_bucket_name"></a> [s3\_bucket\_name](#input\_s3\_bucket\_name) | Name of the S3 bucket to store the conformance pack template | `string` | n/a | yes |
| <a name="input_accounts_key"></a> [accounts\_key](#input\_accounts\_key) | The object key of the account inventory in the policy bucket. When null, no inventory is read and organizational\_path/account\_tag rules are ignored. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | KMS key ID for encrypting CloudWatch Logs (optional) | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | Log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | Number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_config_rule_name"></a> [config\_rule\_name](#input\_config\_rule\_name) | Name of the AWS Config rule within the conformance pack | `string` | `"tagging-compliance"` | no |
| <a name="input_conformance_pack_name"></a> [conformance\_pack\_name](#input\_conformance\_pack\_name) | Name of the AWS Config Conformance Pack | `string` | `"tagging-compliance"` | no |
| <a name="input_deploy_organization_wide"></a> [deploy\_organization\_wide](#input\_deploy\_organization\_wide) | Whether to deploy the conformance pack organization-wide (requires Organizations management account) | `bool` | `false` | no |
| <a name="input_excluded_accounts"></a> [excluded\_accounts](#input\_excluded\_accounts) | List of AWS account IDs to exclude from organization conformance pack deployment | `list(string)` | `[]` | no |
| <a name="input_input_parameters"></a> [input\_parameters](#input\_input\_parameters) | Map of additional input parameters to pass to the conformance pack. PolicyVersion and MappingsVersion are always set from policy\_version and mappings\_version; InventoryVersion is read from the content-sha256 metadata of the inventory object (or none). | `map(string)` | `{}` | no |
| <a name="input_inventory_version"></a> [inventory\_version](#input\_inventory\_version) | Pin the InventoryVersion pack parameter instead of reading the content-sha256 metadata of the inventory object. When set, no S3 data sources are read. Bootstrap: pass "none" on the first apply when the policy bucket is created in the same configuration (the bucket does not exist at plan time), then remove it so the version follows the inventory. | `string` | `null` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN of the KMS key encrypting the policy bucket. When set, the lambda is granted kms:Decrypt on it. | `string` | `null` | no |
| <a name="input_lambda_function_arn"></a> [lambda\_function\_arn](#input\_lambda\_function\_arn) | ARN of the Lambda function that evaluates compliance | `string` | `null` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | The runtime environment for the validation Lambda function (ignored when lambda\_function\_arn is set). | `string` | `"python3.14"` | no |
| <a name="input_mappings_key"></a> [mappings\_key](#input\_mappings\_key) | The object key of the resource type mappings in the policy bucket. | `string` | `"mappings.yaml"` | no |
| <a name="input_max_execution_frequency"></a> [max\_execution\_frequency](#input\_max\_execution\_frequency) | Maximum frequency for Config rule evaluation | `string` | `"TwentyFour_Hours"` | no |
| <a name="input_pack_description"></a> [pack\_description](#input\_pack\_description) | Description of the conformance pack | `string` | `"AWS Config Conformance Pack for validating resource tagging compliance"` | no |
| <a name="input_policy_bucket_arn"></a> [policy\_bucket\_arn](#input\_policy\_bucket\_arn) | The ARN of the S3 bucket holding the tagging policy, mappings and inventory. Required unless lambda\_function\_arn is provided. | `string` | `null` | no |
| <a name="input_policy_bucket_name"></a> [policy\_bucket\_name](#input\_policy\_bucket\_name) | The name of the S3 bucket holding the tagging policy, mappings and inventory. Required unless lambda\_function\_arn is provided. | `string` | `null` | no |
| <a name="input_policy_key"></a> [policy\_key](#input\_policy\_key) | The object key of the tagging policy in the policy bucket. | `string` | `"policy.yaml"` | no |
| <a name="input_resource_types"></a> [resource\_types](#input\_resource\_types) | List of AWS resource types to evaluate (e.g., AWS::EC2::Instance) | `list(string)` | <pre>[<br/>  "AWS::*"<br/>]</pre> | no |
| <a name="input_s3_enable_versioning"></a> [s3\_enable\_versioning](#input\_s3\_enable\_versioning) | Enable versioning for the S3 bucket | `bool` | `true` | no |
| <a name="input_s3_kms_key_id"></a> [s3\_kms\_key\_id](#input\_s3\_kms\_key\_id) | KMS key ID for S3 bucket encryption (optional) | `string` | `null` | no |
| <a name="input_s3_template_key"></a> [s3\_template\_key](#input\_s3\_template\_key) | S3 object key for the conformance pack template | `string` | `"conformance-packs/tagging-compliance.yaml"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_conformance_pack_arn"></a> [conformance\_pack\_arn](#output\_conformance\_pack\_arn) | ARN of the conformance pack |
| <a name="output_conformance_pack_id"></a> [conformance\_pack\_id](#output\_conformance\_pack\_id) | ID of the conformance pack |
| <a name="output_conformance_pack_name"></a> [conformance\_pack\_name](#output\_conformance\_pack\_name) | Name of the conformance pack |
| <a name="output_s3_bucket_arn"></a> [s3\_bucket\_arn](#output\_s3\_bucket\_arn) | ARN of the S3 bucket storing the conformance pack template |
| <a name="output_s3_bucket_name"></a> [s3\_bucket\_name](#output\_s3\_bucket\_name) | Name of the S3 bucket storing the conformance pack template |
| <a name="output_s3_template_uri"></a> [s3\_template\_uri](#output\_s3\_template\_uri) | S3 URI of the conformance pack template |
<!-- END_TF_DOCS -->
