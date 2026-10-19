# AWS Organizations Account Inventory Module

## Introduction

This Terraform module provisions a Lambda function that synchronizes AWS Organizations account information to an S3 bucket in YAML format. It periodically queries the AWS Organizations API to retrieve all accounts, their organizational unit (OU) paths, account status, and account tags, then writes this data to S3 as `accounts.yaml` for use by the tagging compliance framework.

### Key Features

- **Automated Account Discovery**: Automatically retrieves all accounts from AWS Organizations
- **OU Hierarchy Mapping**: Builds complete organizational unit paths (e.g., `root/engineering/platform`)
- **Account Status Tracking**: Records account status (ACTIVE, SUSPENDED, etc.)
- **Account Tags Export**: Captures AWS Organizations account tags for filtering rules by account metadata
- **Structured Logging**: JSON-formatted logs for easy integration with CloudWatch Logs Insights
- **Periodic Synchronization**: Built-in scheduled EventBridge rule for regular syncs
- **Account Event Triggers**: Automatically syncs on account creation, closure, moves, and tag changes (us-east-1 only)
- **Conformance Pack Reconciliation**: Optionally triggers organization-wide Config re-evaluation when inventory changes
- **IAM Best Practices**: Minimal permissions with least-privilege access
- **Encryption Support**: Optional KMS encryption for S3 bucket and CloudWatch Logs

### Module Components

- **AWS Lambda Function**: Python-based handler that queries Organizations API and writes `accounts.yaml` to S3
- **IAM Role & Policy**: Custom role with minimal permissions for Organizations, S3, and optional conformance pack access
- **CloudWatch Logs**: Structured JSON logging with optional encryption and retention policies
- **EventBridge Integration**: Scheduled sync and account event triggers for automatic inventory updates

## Usage

### Basic Example

```hcl
# S3 bucket for storing account inventory
resource "aws_s3_bucket" "policy" {
  bucket = "org-tagging-policy"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Deploy the organizations module
module "organizations_inventory" {
  source = "./modules/organizations"

  # S3 bucket to store account inventory (accounts.yaml)
  bucket_name = aws_s3_bucket.policy.id
  bucket_arn  = aws_s3_bucket.policy.arn
  accounts_key = "accounts.yaml"

  # Lambda configuration
  lambda_name        = "organizations-account-inventory"
  lambda_description = "Synchronizes AWS Organizations account information to S3"
  lambda_runtime     = "python3.12"
  lambda_timeout     = 60
  lambda_memory_size = 128
  lambda_log_level   = "INFO"

  # Scheduled sync (EventBridge)
  enable_scheduled_sync     = true
  scheduled_sync_expression = "rate(1 day)"

  # Account event sync (EventBridge, CloudTrail-backed)
  # Note: Organizations CloudTrail events reach EventBridge only in us-east-1
  enable_account_event_sync = true

  # CloudWatch Logs configuration
  cloudwatch_logs_retention_in_days = 7
  cloudwatch_logs_log_group_class   = "STANDARD"

  # Tags to apply to all resources
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Output the Lambda ARN
output "organizations_lambda_arn" {
  value = module.organizations_inventory.lambda_arn
}
```

### EventBridge Triggers

This module can trigger the sync in two ways:

1. **Scheduled sync** (recommended): uses a schedule expression like `rate(1 day)`.
2. **Account event sync** (recommended): triggers on account creation, closure, moves, and tag changes.

**Important**: AWS Organizations CloudTrail events are delivered to EventBridge only in **us-east-1**. If you deploy this module in another region, the account event trigger will not fire. The scheduled sync will still run normally.

### Account Inventory Format

The Lambda function stores account information in S3 as a YAML file with the following structure:

```yaml
version: 1
accounts:
  "123456789012":
    name: Production Account
    ou_path: root/engineering/platform
    status: ACTIVE
    tags:
      Environment: production
      CostCentre: "42"
  "234567890123":
    name: Development Account
    ou_path: root/engineering/dev
    status: ACTIVE
    tags: {}
```

Each account entry includes:

| Field | Description |
|-------|-------------|
| Account ID (key) | AWS account ID (top-level key in the YAML) |
| `name` | Account name from Organizations |
| `ou_path` | Full organizational unit path (e.g., `root/engineering/platform`) |
| `status` | Account status (ACTIVE, SUSPENDED, etc.) |
| `tags` | AWS Organizations account tags (key-value pairs) |

Account tags are retrieved via `organizations:ListTagsForResource` and enable filtering rules by account metadata (e.g., `filter: {account_tag: {Environment: production}}`).

## How It Works

The Lambda function performs the following operations when invoked:

1. **Build OU Hierarchy**: Queries Organizations API to build a complete map of organizational units
2. **List Accounts**: Retrieves all accounts in the organization using pagination
3. **Determine OU Paths**: For each account, determines its full organizational path (e.g., `root/engineering/platform`)
4. **Retrieve Account Tags**: Queries Organizations API for tags on each account
5. **Generate YAML**: Builds the accounts.yaml structure with all metadata
6. **Check for Changes**: Computes content SHA256 hash and compares with existing object metadata
7. **Write to S3**: Uploads accounts.yaml only if content has changed (sets `content-sha256` metadata)
8. **Reconcile Pack** (optional): If configured, re-puts the organization conformance pack with the new `InventoryVersion` to trigger org-wide re-evaluation

## Use Cases

### 1. Tagging Compliance Rules
The primary use case is enabling organizational path and account tag filters in the tagging policy:

```yaml
version: 1
rules:
  - name: prod-cost-centre
    description: Production accounts require CostCentre tag
    steps:
      - filter: {organizational_path: root/workloads/prod}
      - assert: {tag: CostCentre, present: true}
  
  - name: eu-data-residency
    description: EU accounts require DataLocation tag
    steps:
      - filter: {account_tag: {Region: eu}}
      - assert: {tag: DataLocation, in: [eu-west-1, eu-central-1]}
```

### 2. Account Inventory Reporting
Query the YAML file from S3 to generate reports of all accounts in your organization. This can be useful for operational dashboards and compliance reports.

### 3. Cross-Account Automation
Build automation workflows that need to discover accounts in specific OUs or with specific account tags.

### 4. Automated Re-evaluation
When combined with the conformance pack reconciliation feature, inventory changes automatically trigger organization-wide Config re-evaluation, ensuring compliance rules reflect the current account structure.

## Sync Frequency Recommendations

| Environment | Frequency | EventBridge Expression |
|-------------|-----------|------------------------|
| Production (stable) | Daily | `rate(1 day)` |
| Production (active) | Every 6 hours | `rate(6 hours)` |
| Development | Weekly | `rate(7 days)` |
| Real-time needs | Hourly | `rate(1 hour)` |

## Monitoring and Troubleshooting

### CloudWatch Logs
The Lambda function outputs structured JSON logs. Query them using CloudWatch Logs Insights:

```sql
fields @timestamp, action, account_count, changed
| filter action = "lambda_handler"
| sort @timestamp desc
| limit 20
```

### Successful Execution Example

```json
{
  "timestamp": "2026-10-19T10:30:00.000Z",
  "level": "INFO",
  "logger": "handler",
  "message": "Completed AWS Organizations account inventory sync",
  "action": "lambda_handler",
  "account_count": 47,
  "changed": true
}
```

### Error Detection

```sql
fields @timestamp, message, error
| filter level = "ERROR"
| sort @timestamp desc
```

### Common Issues

**Issue**: Lambda timeout during execution  
**Solution**: Increase `lambda_timeout` (default 60s) or `lambda_memory_size` for large organizations

**Issue**: Organizations API throttling  
**Solution**: Lambda already uses pagination. Consider increasing sync interval if you have hundreds of accounts.

**Issue**: S3 write errors  
**Solution**: Verify Lambda has `s3:PutObject` permission on the bucket and accounts key. Check bucket policy and KMS key policy if encryption is enabled.

**Issue**: Missing accounts in inventory  
**Solution**: Check Lambda logs for errors during account iteration. Partial failures are logged per-account.

**Issue**: Account event trigger not firing  
**Solution**: Verify the module is deployed in us-east-1. Organizations CloudTrail events reach EventBridge only in us-east-1.

**Issue**: Conformance pack reconciliation fails  
**Solution**: Verify `conformance_pack_name` and `conformance_pack_template_uri` are set correctly. Check Lambda has Config and Organizations permissions for re-putting the pack.

## IAM Permissions

The Lambda function requires the following IAM permissions:

### Organizations API Access
```json
{
  "Effect": "Allow",
  "Action": [
    "organizations:List*",
    "organizations:Describe*",
    "organizations:ListTagsForResource"
  ],
  "Resource": "*"
}
```

### S3 Access
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::your-bucket-name/accounts.yaml"
}
```

### KMS Access (when bucket is encrypted)
```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": "arn:aws:kms:region:account-id:key/your-key-id"
}
```

### Conformance Pack Reconciliation (optional)

When `conformance_pack_name` and `conformance_pack_template_uri` are set, additional permissions are required:

```json
{
  "Effect": "Allow",
  "Action": [
    "config:DescribeOrganizationConformancePacks",
    "config:PutOrganizationConformancePack",
    "organizations:DescribeOrganization",
    "organizations:ListAccounts",
    "organizations:ListDelegatedAdministrators",
    "organizations:EnableAWSServiceAccess",
    "iam:CreateServiceLinkedRole",
    "iam:GetRole",
    "s3:GetObject"
  ],
  "Resource": "*"
}
```

The conformance pack permissions enable the Lambda to re-put the organization conformance pack with a new `InventoryVersion` parameter when the account inventory changes, forcing an organization-wide Config re-evaluation.

**Note**: The module automatically creates all required permissions. This reference is provided for documentation purposes.

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_bucket_arn"></a> [bucket\_arn](#input\_bucket\_arn) | The ARN of the S3 bucket the account inventory is written to. | `string` | n/a | yes |
| <a name="input_bucket_name"></a> [bucket\_name](#input\_bucket\_name) | The name of the S3 bucket the account inventory is written to. | `string` | n/a | yes |
| <a name="input_account_event_rule_name"></a> [account\_event\_rule\_name](#input\_account\_event\_rule\_name) | Name of the EventBridge rule used for account event syncs. | `string` | `"organizations-account-inventory-account-events"` | no |
| <a name="input_accounts_key"></a> [accounts\_key](#input\_accounts\_key) | The object key of the account inventory (YAML) written to the bucket. | `string` | `"accounts.yaml"` | no |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_conformance_pack_name"></a> [conformance\_pack\_name](#input\_conformance\_pack\_name) | The name of the organization conformance pack to re-put with a new InventoryVersion when the inventory changes, forcing an org-wide re-evaluation. Requires conformance\_pack\_template\_uri. When null, no re-evaluation is triggered. | `string` | `null` | no |
| <a name="input_conformance_pack_template_uri"></a> [conformance\_pack\_template\_uri](#input\_conformance\_pack\_template\_uri) | The S3 URI (s3://bucket/key) of the conformance pack template (the pack module's s3\_bucket\_name and s3\_template\_key, e.g. built with format(); referencing its s3\_template\_uri output from the root module creates a dependency cycle). Required with conformance\_pack\_name because DescribeOrganizationConformancePacks does not return the template location. | `string` | `null` | no |
| <a name="input_enable_account_event_sync"></a> [enable\_account\_event\_sync](#input\_enable\_account\_event\_sync) | Enable an EventBridge rule to trigger the sync on account create, close, move, tag and untag events. Organizations CloudTrail events are delivered to EventBridge only in us-east-1, so the module must be deployed in us-east-1 for this trigger to fire; elsewhere only the scheduled sync runs. | `bool` | `true` | no |
| <a name="input_enable_scheduled_sync"></a> [enable\_scheduled\_sync](#input\_enable\_scheduled\_sync) | Enable a scheduled EventBridge rule to trigger the sync periodically. | `bool` | `true` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN of the KMS key encrypting the bucket. When set, the lambda is granted kms:Decrypt and kms:GenerateDataKey on it. | `string` | `null` | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function to synchronize AWS Organizations account information. | `string` | `"Synchronizes AWS Organizations account information to S3."` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL. | `string` | `"INFO"` | no |
| <a name="input_lambda_memory_size"></a> [lambda\_memory\_size](#input\_lambda\_memory\_size) | The amount of memory in MB allocated to the Lambda function. | `number` | `128` | no |
| <a name="input_lambda_name"></a> [lambda\_name](#input\_lambda\_name) | The name of the Lambda function to synchronize AWS Organizations account information. | `string` | `"organizations-account-inventory"` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | The runtime environment for the Lambda function. | `string` | `"python3.12"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | The timeout for the Lambda function in seconds. | `number` | `60` | no |
| <a name="input_scheduled_sync_expression"></a> [scheduled\_sync\_expression](#input\_scheduled\_sync\_expression) | EventBridge schedule expression for periodic sync (e.g., rate(1 day), cron(0 2 * * ? *)). | `string` | `"rate(1 day)"` | no |
| <a name="input_scheduled_sync_rule_name"></a> [scheduled\_sync\_rule\_name](#input\_scheduled\_sync\_rule\_name) | Name of the EventBridge rule used for scheduled syncs. | `string` | `"organizations-account-inventory-schedule"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to the Lambda function. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_account_event_pattern"></a> [account\_event\_pattern](#output\_account\_event\_pattern) | The EventBridge event pattern of the account event rule, or null when the account event sync is disabled. |
| <a name="output_lambda_arn"></a> [lambda\_arn](#output\_lambda\_arn) | The ARN of the Lambda function for tagging compliance. |
| <a name="output_lambda_name"></a> [lambda\_name](#output\_lambda\_name) | The name of the Lambda function for tagging compliance. |
<!-- END_TF_DOCS -->