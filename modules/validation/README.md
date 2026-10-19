# AWS Tagging Validation Module

## Introduction

This Terraform module provisions a Lambda function that evaluates tagging compliance across your AWS resources. It reads a YAML tagging policy, resource type mappings, and optional account inventory from S3, then evaluates resources against the policy rules and marks them as compliant or non-compliant.

### Key Features

- **YAML Policy Engine**: Define rules in a declarative YAML policy with support for:
  - Required tag assertions
  - Permitted values and regex pattern matching
  - Account ID, organizational path, and account tag filtering
  - Multi-step rule chains with filters and assertions
- **S3-Based Storage**: Policy, mappings, and inventory stored in S3 with organization-wide read access
- **High Performance Caching**: Optional in-memory caching with ETag revalidation reduces S3 reads by 80-90% and improves response times
- **Structured Logging**: JSON-formatted logs for easy integration with CloudWatch Logs Insights
- **IAM Best Practices**: Minimal permissions with least-privilege access
- **Encryption Support**: Optional KMS encryption for CloudWatch Logs and S3 bucket
- **Automatic Failover**: Serves stale cached policy if S3 is unavailable and logs a warning

### Module Components

- **AWS Lambda Function**: Python-based handler that evaluates resource tags against a YAML policy loaded from S3
- **IAM Role & Policy**: Custom role with minimal permissions for Lambda, Config, and S3 access
- **CloudWatch Logs**: Structured JSON logging with optional encryption and retention policies

## Usage

### Basic Example

```hcl
module "tagging_validation" {
  source = "./modules/validation"

  # S3 bucket containing tagging policy and mappings
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"  # Optional: for organizational_path/account_tag filters

  # Lambda configuration
  lambda_name        = "tagging-compliance-handler"
  lambda_description = "Evaluates tagging compliance for AWS resources"
  lambda_runtime     = "python3.14"
  lambda_timeout     = 30
  lambda_log_level   = "INFO"
  lambda_role_name   = "tagging-compliance-lambda-role"

  # Rules caching configuration (optional, improves performance)
  rules_cache_enabled     = true   # Enable in-memory caching of policy/mappings/inventory
  rules_cache_ttl_seconds = 300    # Cache objects for 5 minutes

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

### Policy Configuration in S3

Compliance rules are defined in a YAML policy file stored in S3. The policy uses a declarative syntax with filter and assert steps.

#### Policy Structure

```yaml
version: 1
rules:
  - name: rule-name
    description: Human-readable description
    steps:
      - filter: {type: aws_ec2_instance}           # Narrow scope to resource types
      - filter: {account_id: ["123456789012"]}     # Filter by account ID
      - assert: {tag: Environment, present: true}  # Require tag presence
      - assert: {tag: Environment, in: [Production, Staging]}  # Require specific values
```

#### Filter Step Reference

| Filter Type | Description | Example |
|-------------|-------------|---------|
| `type` | Match Terraform resource types | `{type: aws_s3_bucket}` or `{type: [aws_ec2_instance, aws_ec2_volume]}` |
| `account_id` | Match AWS account IDs | `{account_id: ["123456789012", "210987654321"]}` |
| `organizational_path` | Match AWS Organizations path (requires inventory) | `{organizational_path: root/Production}` |
| `account_tag` | Match account tags (requires inventory) | `{account_tag: {Environment: Production}}` |
| `tag` | Match resource tags | `{tag: Environment, present: true}` or `{tag: Environment, equals: Production}` |

#### Assert Step Reference

| Assertion | Description | Example |
|-----------|-------------|---------|
| `present` | Tag must exist | `{tag: Environment, present: true}` |
| `equals` | Tag value must equal | `{tag: Environment, equals: Production}` |
| `in` | Tag value must be in list | `{tag: Environment, in: [Production, Staging]}` |
| `matches` | Tag value must match regex | `{tag: Owner, matches: "^[a-z]+@company\\.com$"}` |
| `starts_with` | Tag value must start with string | `{tag: GitRepo, starts_with: "https://github.com/"}` |
| `contains` | Tag value must contain substring | `{tag: Name, contains: production}` |
| `not` | Negate an assertion | `{tag: Environment, equals: default, not: true}` |

## Examples

### Example 1: Enforce Environment Tags

```yaml
version: 1
rules:
  - name: require-environment-tag
    description: All EC2 resources must have valid Environment tag
    steps:
      - filter: {type: [aws_ec2_instance, aws_ec2_volume]}
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [production, staging, development, sandbox]}
```

### Example 2: Enforce Owner Email Tag (Pattern-based)

```yaml
version: 1
rules:
  - name: require-owner-email
    description: All resources must have Owner email from company domain
    steps:
      - assert: {tag: Owner, present: true}
      - assert: {tag: Owner, matches: "^[a-zA-Z0-9._%+-]+@company\\.com$"}
```

### Example 3: Account-Specific Cost Center Requirement

```yaml
version: 1
rules:
  - name: prod-cost-center
    description: Production accounts require CostCenter tag on databases
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

# Deploy the validation module
module "tagging_validation" {
  source = "./modules/validation"

  policy_bucket_name = data.aws_s3_bucket.policy_bucket.id
  policy_bucket_arn  = data.aws_s3_bucket.policy_bucket.arn
  policy_key         = "policy.yaml"
  mappings_key       = "mappings.yaml"
  accounts_key       = "accounts.yaml"

  lambda_name        = "tagging-compliance"
  lambda_description = "Evaluates resource tagging compliance"
  lambda_log_level   = "DEBUG"
  lambda_runtime     = "python3.14"
  lambda_timeout     = 60
  lambda_memory_size = 256

  # Enable caching for better performance
  rules_cache_enabled     = true
  rules_cache_ttl_seconds = 300

  cloudwatch_logs_retention_in_days = 14
  cloudwatch_logs_kms_key_id        = aws_kms_key.logs.id

  # Optional: if policy bucket is encrypted with KMS
  kms_key_arn = aws_kms_key.policy_bucket.arn

  tags = {
    Environment = "production"
    Team        = "platform-engineering"
  }
}

# Output Lambda function details
output "lambda_function_arn" {
  value = module.tagging_validation.lambda_arn
}
```

## Compliance Evaluation Logic

The Lambda function evaluates resources against the YAML policy using the following logic:

1. **Policy Loading**: Load policy.yaml, mappings.yaml, and accounts.yaml (if configured) from S3 with optional caching
2. **Type Mapping**: Map AWS Config resource type to Terraform type using mappings.yaml (e.g., `AWS::S3::Bucket` → `aws_s3_bucket`)
3. **Rule Evaluation**: For each rule in the policy:
   - Apply filter steps to determine if the rule applies to the resource
   - Execute assert steps to check tag requirements
   - Stop at the first assert that fails (error-severity violation)
4. **Result Determination**: Mark resource as:
   - **NON_COMPLIANT**: One or more error-severity violations found (annotation limited to 256 chars)
   - **COMPLIANT**: No error-severity violations (warnings are allowed)
   - **NOT_APPLICABLE**: No rules reached an assert step, Config type not in mappings, or resource is deleted

## Performance Optimization: Policy Caching

### Overview

The Lambda function supports optional in-memory caching of the policy, mappings, and inventory to significantly reduce S3 read costs and improve evaluation performance. When enabled, S3 objects are cached in Lambda's execution environment with ETag-based revalidation.

### Benefits

- **Cost Reduction**: Reduces S3 GET requests by 80-90% in typical workloads
- **Performance**: Faster evaluation times by eliminating S3 API calls on cache hits
- **ETag Revalidation**: After TTL expires, Lambda revalidates with the S3 ETag (304 response keeps cached copy)
- **Automatic Failover**: If S3 errors and a cached copy exists, serves the stale copy and logs a warning
- **Validation**: Invalid YAML or policy raises an error immediately (no evaluations are put)

### Configuration

```hcl
module "tagging_validation" {
  source = "./modules/validation"

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

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_policy_bucket_arn"></a> [policy\_bucket\_arn](#input\_policy\_bucket\_arn) | The ARN of the S3 bucket holding the tagging policy, mappings and inventory. | `string` | n/a | yes |
| <a name="input_policy_bucket_name"></a> [policy\_bucket\_name](#input\_policy\_bucket\_name) | The name of the S3 bucket holding the tagging policy, mappings and inventory. | `string` | n/a | yes |
| <a name="input_accounts_key"></a> [accounts\_key](#input\_accounts\_key) | The object key of the account inventory in the policy bucket. When null, no inventory is read and organizational\_path/account\_tag rules are ignored. | `string` | `null` | no |
| <a name="input_allowed_source_accounts"></a> [allowed\_source\_accounts](#input\_allowed\_source\_accounts) | List of AWS account IDs allowed to invoke this Lambda function. If not provided and organization\_id is set, allows all accounts in the organization. | `list(string)` | `[]` | no |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
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
| <a name="input_organizations_id"></a> [organizations\_id](#input\_organizations\_id) | AWS Organization ID to allow cross-account invocation. | `string` | `null` | no |
| <a name="input_policy_key"></a> [policy\_key](#input\_policy\_key) | The object key of the tagging policy in the policy bucket. | `string` | `"policy.yaml"` | no |
| <a name="input_rules_cache_enabled"></a> [rules\_cache\_enabled](#input\_rules\_cache\_enabled) | Enable or disable caching of the policy, mappings and inventory in Lambda function memory. | `bool` | `true` | no |
| <a name="input_rules_cache_ttl_seconds"></a> [rules\_cache\_ttl\_seconds](#input\_rules\_cache\_ttl\_seconds) | Time-to-live (TTL) in seconds for the cached policy, mappings and inventory before they are revalidated against S3. | `number` | `300` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the Lambda function. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_environment_variables"></a> [environment\_variables](#output\_environment\_variables) | The environment variables configured on the Lambda function (policy bucket, object keys, cache and log settings). |
| <a name="output_lambda_arn"></a> [lambda\_arn](#output\_lambda\_arn) | The ARN of the Lambda function for tagging compliance. |
| <a name="output_lambda_name"></a> [lambda\_name](#output\_lambda\_name) | The name of the Lambda function for tagging compliance. |
<!-- END_TF_DOCS -->