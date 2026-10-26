# AWS Config Tagging Compliance Module

## Introduction

This Terraform module provisions an AWS Config custom rule that evaluates tagging compliance across your AWS resources. It integrates with a separate validation Lambda module that reads a YAML tagging policy from S3 and automatically evaluates resources against the policy, marking them as compliant or non-compliant.

### Key Features

- **Modular Architecture**: Separates AWS Config rules from Lambda function management
- **Custom AWS Config Rules**: Automatically evaluate resources for tagging compliance
- **YAML Policy Engine**: Define rules in a declarative YAML policy stored in S3 with support for:
  - Required tag assertions
  - Permitted values and regex pattern matching
  - Account ID, organizational path, and account tag filtering
  - Multi-step rule chains with filters and assertions
- **High Performance Caching**: Optional in-memory caching with ETag revalidation reduces S3 reads by 80-90% and improves response times
- **Cross-Account Lambda Support**: Allow any account in your organization to invoke the Lambda
- **Structured Logging**: JSON-formatted logs for easy integration with CloudWatch Logs Insights
- **IAM Best Practices**: Minimal permissions with least-privilege access
- **Encryption Support**: Optional KMS encryption for CloudWatch Logs and S3 bucket
- **Automatic Re-evaluation**: Policy and mappings version hashes trigger Config to re-evaluate all resources

### Module Components

- **AWS Lambda Function**: Python-based handler deployed via `../validation` module that evaluates resource tags against a YAML policy loaded from S3
- **AWS Config Custom Rule**: Invokes the Lambda function to assess resource compliance
- **Lambda Permissions**: Grants cross-account and organization-wide invocation rights
- **CloudWatch Logs**: Structured JSON logging with optional encryption and retention policies

## Architecture

The config module integrates with the validation module to load policy from S3:

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
│  • S3 policy loader           │
└────────────┬──────────────────┘
             │
             │ Reads (cross-account)
             ▼
┌──────────────────────────────┐
│  S3 Bucket (Management Acct)  │
│                               │
│  • policy.yaml                │
│  • mappings.yaml              │
│  • accounts.yaml (optional)   │
└──────────────────────────────┘
```

## Usage

### Basic Example (Same Account)

```hcl
module "config_tagging_compliance" {
  source = "./modules/config"

  # S3 bucket containing tagging policy and mappings
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."  # From root module output
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."  # From root module output
  accounts_key       = "accounts.yaml"

  # Lambda configuration (passed to validation module)
  lambda_name        = "tagging-compliance-handler"
  lambda_description = "Evaluates tagging compliance for AWS resources"
  lambda_runtime     = "python3.14"
  lambda_timeout     = 30
  lambda_log_level   = "INFO"
  lambda_role_name   = "tagging-compliance-lambda-role"

  # Policy caching configuration (optional, improves performance)
  rules_cache_enabled     = true   # Enable in-memory caching of policy/mappings/inventory
  rules_cache_ttl_seconds = 300    # Cache objects for 5 minutes

  # AWS Config rule configuration
  config_name                  = "tagging-compliance"
  maximum_execution_frequency  = "TwentyFour_Hours"
  periodic_evaluation_enabled  = true
  config_resource_types        = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::RDS::DBInstance"]

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

The `config` module delegates Lambda function management to the `validation` module for better separation of concerns:

- **config module**: Manages AWS Config rules and Lambda permissions
- **validation module**: Manages Lambda function, IAM roles, logging, and S3 policy loading

This allows you to:
- Share a single Lambda across multiple Config rules
- Manage Lambda and Config separately
- Reuse the validation module for other purposes

If you need to customize the Lambda function beyond what this module provides, you can directly use the validation module.

### Policy Configuration in S3

Compliance rules are defined in a YAML policy file stored in S3. The policy uses a declarative syntax with filter and assert steps.

#### Example Policy

```yaml
version: 1
rules:
  - name: require-environment-tag
    description: All resources must have valid Environment tag
    steps:
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [production, staging, development]}

  - name: require-owner-email
    description: All resources must have Owner email
    steps:
      - assert: {tag: Owner, present: true}
      - assert: {tag: Owner, matches: "^[a-zA-Z0-9._%+-]+@company\\.com$"}

  - name: prod-cost-center
    description: Production accounts require CostCenter
    steps:
      - filter: {account_id: ["111222333444"]}
      - assert: {tag: CostCenter, present: true}
```

For complete policy syntax and examples, see the [root module README](../../README.md#policy) and [validation module documentation](../validation/README.md).

## Examples

### Example 1: Enforce Environment Tags

Add this rule to your `policy.yaml`:

```yaml
- name: require-environment-tag
  description: All EC2 resources must have valid Environment tag
  steps:
    - filter: {type: [aws_ec2_instance, aws_ec2_volume]}
    - assert: {tag: Environment, present: true}
    - assert: {tag: Environment, in: [production, staging, development, sandbox]}
```

### Example 2: Enforce Owner Email Tag (Pattern-based)

Add this rule to your `policy.yaml`:

```yaml
- name: require-owner-email
  description: All resources must have Owner email from company domain
  steps:
    - assert: {tag: Owner, present: true}
    - assert: {tag: Owner, matches: "^[a-zA-Z0-9._%+-]+@company\\.com$"}
```

### Example 3: Account-Specific Cost Center Requirement

Add this rule to your `policy.yaml`:

```yaml
- name: prod-cost-center
  description: Production accounts require CostCenter on databases
  steps:
    - filter: {type: [aws_db_instance, aws_rds_cluster]}
    - filter: {account_id: ["123456789012", "210987654321"]}
    - assert: {tag: CostCenter, present: true}
    - assert: {tag: CostCenter, in: [CC-001, CC-002, CC-003]}
```

### Example 4: Full Module Configuration

```hcl
# Reference the S3 bucket with policy and mappings (created by root module)
data "aws_s3_bucket" "policy_bucket" {
  bucket = "org-tagging-compliance"
}

# Deploy the config module
module "config_tagging_compliance" {
  source = "./modules/config"

  policy_bucket_name = data.aws_s3_bucket.policy_bucket.id
  policy_bucket_arn  = data.aws_s3_bucket.policy_bucket.arn
  policy_key         = "policy.yaml"
  policy_version     = var.policy_version  # Pass from root module output
  mappings_key       = "mappings.yaml"
  mappings_version   = var.mappings_version  # Pass from root module output
  accounts_key       = "accounts.yaml"

  lambda_name        = "tagging-compliance"
  lambda_description = "Evaluates resource tagging compliance via AWS Config"
  lambda_log_level   = "DEBUG"
  lambda_runtime     = "python3.14"
  lambda_timeout     = 60

  config_name                  = "resource-tagging-compliance"
  maximum_execution_frequency  = "Six_Hours"
  periodic_evaluation_enabled  = true
  config_resource_types        = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::Lambda::Function"]

  cloudwatch_logs_retention_in_days = 14
  cloudwatch_logs_kms_key_id        = aws_kms_key.logs.id

  # Optional: if policy bucket is encrypted with KMS
  kms_key_arn = var.policy_bucket_kms_key_arn

  tags = {
    Environment = "production"
    Team        = "platform-engineering"
  }
}

# Output compliance status
output "config_rule_arn" {
  value = module.config_tagging_compliance.config_arn
}

output "lambda_function_arn" {
  value = module.config_tagging_compliance.lambda_arn
}
```

## Compliance Evaluation Logic

The Lambda function evaluates resources against the YAML policy using the following logic:

1. **Policy Loading**: Load policy.yaml, mappings.yaml, and accounts.yaml (if configured) from S3 with optional caching
2. **Type Mapping**: Map AWS Config resource type to Terraform type using mappings.yaml
3. **Rule Evaluation**: For each rule in the policy:
   - Apply filter steps to determine if the rule applies to the resource
   - Execute assert steps to check tag requirements
   - Stop at the first assert that fails (error-severity violation)
4. **Result Determination**: Mark resource as:
   - **NON_COMPLIANT**: One or more error-severity violations found
   - **COMPLIANT**: No error-severity violations (warnings are allowed)
   - **NOT_APPLICABLE**: No rules reached an assert step, Config type not in mappings, or resource is deleted
5. **Re-evaluation Triggers**: AWS Config re-evaluates all resources when `policy_version` or `mappings_version` input parameters change

**Note**: Per-account Config rules are NOT re-evaluated when the account inventory changes. The handler does not support ScheduledNotification events. For automatic re-evaluation on inventory changes, use the pack module with the organizations Lambda.

## Performance Optimization: Policy Caching

### Overview

The Lambda function supports optional in-memory caching of the policy, mappings, and inventory to significantly reduce S3 read costs and improve evaluation performance. When enabled, S3 objects are cached with ETag-based revalidation.

### Benefits

- **Cost Reduction**: Reduces S3 GET requests by 80-90% in typical workloads
- **Performance**: Faster evaluation times by eliminating S3 API calls on cache hits
- **ETag Revalidation**: After TTL expires, Lambda revalidates with the S3 ETag (304 response keeps cached copy)
- **Automatic Failover**: If S3 errors and a cached copy exists, serves the stale copy and logs a warning

### Configuration

```hcl
module "config_tagging_compliance" {
  source = "./modules/config"

  # ... other configuration ...

  # Enable policy caching (default: true)
  rules_cache_enabled = true

  # Cache TTL in seconds (default: 300)
  # Objects are revalidated with ETag after this period
  rules_cache_ttl_seconds = 300  # 5 minutes
}
```

### How It Works

1. **First Invocation (Cold Start)**: Lambda fetches policy, mappings, and inventory from S3 and caches them with their ETags
2. **Subsequent Invocations (Warm Start)**: Lambda reuses cached objects if TTL hasn't expired
3. **Cache Revalidation**: After TTL expires, Lambda sends conditional GET with ETag; S3 returns 304 if unchanged
4. **S3 Failure Handling**: If S3 errors and a cached copy exists, Lambda serves the stale copy and logs a warning
5. **Container Recycling**: When AWS recycles the Lambda container, cache is reset

### Trade-offs

**Advantages:**
- Significant cost savings on S3 GET requests
- Improved Lambda execution time
- Graceful degradation when S3 is unavailable
- ETag revalidation minimizes unnecessary data transfer

**Considerations:**
- Policy changes take up to TTL seconds to propagate to all Lambda containers
- Multiple Lambda containers may have slightly stale policies during the TTL window
- For most use cases, a 5-minute delay is acceptable given the cost savings

### Recommendations

- **Production workloads**: Enable caching with 300-600 second TTL
- **Testing/development**: Disable caching or use shorter TTL (60 seconds) for faster iteration
- **High-frequency changes**: Use shorter TTL (60-120 seconds) if policy changes frequently
- **Cost optimization**: Use longer TTL (600-3600 seconds) for stable policies

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
- Remediate resources or update policy as needed

### Common Issues

- **No matching rules found**: Verify the rule filters match your resource types and accounts
- **Lambda timeout**: Increase `lambda_timeout` if evaluating complex policies
- **Permission errors**: Verify Lambda role has S3 read access and kms:Decrypt if bucket is encrypted
- **Invalid YAML**: Policy syntax errors cause immediate failure; validate with `policy.py` before deploying
- **Stale policy served**: Check CloudWatch logs for warnings about S3 errors; cached copy is being used
- **Resources not re-evaluated**: Verify `policy_version` and `mappings_version` are set correctly and change when policy updates

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_config_resource_types"></a> [config\_resource\_types](#input\_config\_resource\_types) | List of AWS resource types to evaluate (https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html) | `list(string)` | n/a | yes |
| <a name="input_mappings_version"></a> [mappings\_version](#input\_mappings\_version) | A hash of the mappings content (root module output mappings\_version). Changing it forces AWS Config to re-evaluate all resources. | `string` | n/a | yes |
| <a name="input_policy_bucket_arn"></a> [policy\_bucket\_arn](#input\_policy\_bucket\_arn) | The ARN of the S3 bucket holding the tagging policy, mappings and inventory. | `string` | n/a | yes |
| <a name="input_policy_bucket_name"></a> [policy\_bucket\_name](#input\_policy\_bucket\_name) | The name of the S3 bucket holding the tagging policy, mappings and inventory. | `string` | n/a | yes |
| <a name="input_policy_version"></a> [policy\_version](#input\_policy\_version) | A hash of the tagging policy content (root module output policy\_version). Changing it forces AWS Config to re-evaluate all resources. | `string` | n/a | yes |
| <a name="input_accounts_key"></a> [accounts\_key](#input\_accounts\_key) | The object key of the account inventory in the policy bucket. When null, no inventory is read and organizational\_path/account\_tag rules are ignored. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_config_name"></a> [config\_name](#input\_config\_name) | The name of the AWS Config rule | `string` | `"tagging-compliance"` | no |
| <a name="input_configuration_item_change_enabled"></a> [configuration\_item\_change\_enabled](#input\_configuration\_item\_change\_enabled) | When true, the rule is invoked when AWS Config records a configuration change (including oversized configuration notifications) for resources in scope. Set to false and enable periodic\_evaluation\_enabled to run only on a schedule. | `bool` | `true` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN of the KMS key encrypting the policy bucket. When set, the lambda is granted kms:Decrypt on it. | `string` | `null` | no |
| <a name="input_lambda_architectures"></a> [lambda\_architectures](#input\_lambda\_architectures) | The lambda architecture to use. Valid values are x86\_64 and arm64. | `list(string)` | <pre>[<br/>  "arm64"<br/>]</pre> | no |
| <a name="input_lambda_artifacts_dir"></a> [lambda\_artifacts\_dir](#input\_lambda\_artifacts\_dir) | The directory to store any generated artifacts for the lambda | `string` | `"builds"` | no |
| <a name="input_lambda_create_role"></a> [lambda\_create\_role](#input\_lambda\_create\_role) | Indicates we should create the role | `bool` | `true` | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function to handle AWS Organization account movements. | `string` | `"Handles AWS Organization account movements for tagging compliance."` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL. | `string` | `"INFO"` | no |
| <a name="input_lambda_memory_size"></a> [lambda\_memory\_size](#input\_lambda\_memory\_size) | The amount of memory in MB allocated to the Lambda function. | `number` | `128` | no |
| <a name="input_lambda_name"></a> [lambda\_name](#input\_lambda\_name) | The name of the Lambda function to handle AWS Organization account movements. | `string` | `"lz-tagging-compliance"` | no |
| <a name="input_lambda_role_name"></a> [lambda\_role\_name](#input\_lambda\_role\_name) | The name of the IAM role to be created for the Lambda function. | `string` | `"lz-tagging-compliance"` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | The runtime environment for the Lambda function. | `string` | `"python3.14"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | The timeout for the Lambda function in seconds. | `number` | `30` | no |
| <a name="input_mappings_key"></a> [mappings\_key](#input\_mappings\_key) | The object key of the resource type mappings in the policy bucket. | `string` | `"mappings.yaml"` | no |
| <a name="input_maximum_execution_frequency"></a> [maximum\_execution\_frequency](#input\_maximum\_execution\_frequency) | Maximum interval between periodic evaluations when periodic\_evaluation\_enabled is true. Values: One\_Hour, Three\_Hours, Six\_Hours, Twelve\_Hours, TwentyFour\_Hours. | `string` | `"TwentyFour_Hours"` | no |
| <a name="input_periodic_evaluation_enabled"></a> [periodic\_evaluation\_enabled](#input\_periodic\_evaluation\_enabled) | When true, AWS Config also invokes the rule on a recurring schedule; use maximum\_execution\_frequency to set how often. Combine with configuration\_item\_change\_enabled for both change-driven and scheduled evaluations. | `bool` | `false` | no |
| <a name="input_policy_key"></a> [policy\_key](#input\_policy\_key) | The object key of the tagging policy in the policy bucket. | `string` | `"policy.yaml"` | no |
| <a name="input_rules_cache_enabled"></a> [rules\_cache\_enabled](#input\_rules\_cache\_enabled) | Enable or disable caching of compliance rules in Lambda function memory. When enabled, the policy, mappings and inventory are cached between invocations to reduce S3 reads and improve performance. | `bool` | `true` | no |
| <a name="input_rules_cache_ttl_seconds"></a> [rules\_cache\_ttl\_seconds](#input\_rules\_cache\_ttl\_seconds) | Time-to-live (TTL) in seconds for the cached policy, mappings and inventory. After this period, the cached objects are revalidated against S3. Default is 300 seconds (5 minutes). | `number` | `300` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the Lambda function. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_config_arn"></a> [config\_arn](#output\_config\_arn) | The ARN of the AWS Config rule for tagging compliance. |
| <a name="output_lambda_arn"></a> [lambda\_arn](#output\_lambda\_arn) | The ARN of the Lambda function for tagging compliance. |
<!-- END_TF_DOCS -->