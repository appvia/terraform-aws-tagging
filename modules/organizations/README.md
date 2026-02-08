# AWS Organizations Account Inventory Module

## Introduction

This Terraform module provisions a Lambda function that synchronizes AWS Organizations account information to a DynamoDB table. It periodically queries the AWS Organizations API to retrieve all accounts, their organizational unit (OU) paths, and status, then stores this data in DynamoDB for easy querying and reporting.

### Key Features

- **Automated Account Discovery**: Automatically retrieves all accounts from AWS Organizations
- **OU Hierarchy Mapping**: Builds complete organizational unit paths (e.g., `root/engineering/platform`)
- **Account Status Tracking**: Records account status (ACTIVE, SUSPENDED, etc.)
- **Structured Logging**: JSON-formatted logs for easy integration with CloudWatch Logs Insights
- **Periodic Synchronization**: Built-in scheduled EventBridge rule for regular syncs
- **Account Event Triggers**: Optional EventBridge rule to sync on account creation/closure events
- **IAM Best Practices**: Minimal permissions with least-privilege access
- **Encryption Support**: Optional KMS encryption for CloudWatch Logs

### Module Components

- **AWS Lambda Function**: Python-based handler that queries Organizations API and stores data in DynamoDB
- **IAM Role & Policy**: Custom role with minimal permissions for Organizations and DynamoDB access
- **CloudWatch Logs**: Structured JSON logging with optional encryption and retention policies
- **EventBridge Integration**: Ready for periodic invocation via EventBridge scheduled rules

## Usage

### Basic Example

```hcl
# DynamoDB table for storing account inventory
resource "aws_dynamodb_table" "accounts" {
  name           = "organizations-account-inventory"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "AccountId"
  
  attribute {
    name = "AccountId"
    type = "S"
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Deploy the organizations module
module "organizations_inventory" {
  source = "./modules/organizations"

  # DynamoDB table to store account information
  dynamodb_table_arn = aws_dynamodb_table.accounts.arn

  # Lambda configuration
  lambda_name        = "organizations-account-inventory"
  lambda_description = "Synchronizes AWS Organizations account information to DynamoDB"
  lambda_runtime     = "python3.12"
  lambda_timeout     = 60
  lambda_memory_size = 128
  lambda_log_level   = "INFO"

  # Scheduled sync (EventBridge)
  enable_scheduled_sync     = true
  scheduled_sync_expression = "rate(1 day)"

  # Account event sync (EventBridge, CloudTrail-backed)
  enable_account_event_sync = true
  account_event_pattern = jsonencode({
    source      = ["aws.organizations"],
    detail-type = ["AWS API Call via CloudTrail"],
    detail = {
      eventSource = ["organizations.amazonaws.com"],
      eventName   = ["CreateAccount", "CloseAccount"]
    }
  })

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
2. **Account event sync** (optional): triggers on account creation/closure events using EventBridge event patterns.

For account events, the default pattern targets AWS Organizations API calls through CloudTrail (`CreateAccount`, `CloseAccount`). You can customize the pattern to match your specific requirements.

### DynamoDB Table Schema

The Lambda function stores account information in DynamoDB with the following structure:

| Attribute | Type | Description |
|-----------|------|-------------|
| `AccountId` | String | AWS account ID (partition key) |
| `AccountName` | String | Account name from Organizations |
| `OUPath` | String | Full organizational unit path (e.g., `root/engineering/platform`) |
| `Status` | String | Account status (ACTIVE, SUSPENDED, etc.) |
| `LastUpdated` | String | ISO 8601 timestamp of last sync |

### Example DynamoDB Item

```json
{
  "AccountId": "123456789012",
  "AccountName": "Production Account",
  "OUPath": "root/engineering/platform",
  "Status": "ACTIVE",
  "LastUpdated": "2026-02-08T10:30:00.000Z"
}
```

## How It Works

The Lambda function performs the following operations when invoked:

1. **Build OU Hierarchy**: Queries Organizations API to build a complete map of organizational units
2. **List Accounts**: Retrieves all accounts in the organization using pagination
3. **Determine OU Paths**: For each account, determines its full organizational path (e.g., `root/engineering/platform`)
4. **Store in DynamoDB**: Writes account information to DynamoDB with current timestamp

## Use Cases

### 1. Account Inventory Reporting
Query DynamoDB to generate reports of all accounts in your organization:

```python
import boto3

dynamodb = boto3.client('dynamodb')

# Get all accounts in a specific OU
response = dynamodb.scan(
    TableName='organizations-account-inventory',
    FilterExpression='begins_with(OUPath, :ou_path)',
    ExpressionAttributeValues={
        ':ou_path': {'S': 'root/engineering'}
    }
)
```

### 2. Cost Allocation and Tagging
Use account inventory data to drive automated tagging of resources based on OU structure.

### 3. Compliance and Governance
Track account status and OU placement for compliance reporting.

### 4. Cross-Account Automation
Build automation workflows that need to discover accounts in specific OUs.

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
fields @timestamp, action, account_count, stored_count
| filter action = "lambda_handler"
| sort @timestamp desc
| limit 20
```

### Successful Execution Example

```json
{
  "timestamp": "2026-02-08T10:30:00.000Z",
  "level": "INFO",
  "logger": "handler",
  "message": "Completed AWS Organizations account inventory sync",
  "action": "lambda_handler",
  "stored_count": 47,
  "total_count": 47
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

**Issue**: DynamoDB write errors  
**Solution**: Verify Lambda has `dynamodb:PutItem` permission and table ARN is correct

**Issue**: Missing accounts in DynamoDB  
**Solution**: Check Lambda logs for errors during account iteration. Partial failures are logged per-account.

## IAM Permissions

The Lambda function requires the following IAM permissions:

### Organizations API Access
```json
{
  "Effect": "Allow",
  "Action": [
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccounts",
    "organizations:ListParents"
  ],
  "Resource": "*"
}
```

### DynamoDB Access
```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:PutItem"
  ],
  "Resource": "arn:aws:dynamodb:region:account-id:table/your-table-name"
}
```

**Note**: The module automatically creates these permissions. This reference is provided for documentation purposes.

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dynamodb_table_arn"></a> [dynamodb\_table\_arn](#input\_dynamodb\_table\_arn) | The ARN of the DynamoDB table to store AWS Organizations account information. | `string` | n/a | yes |
| <a name="input_account_event_rule_name"></a> [account\_event\_rule\_name](#input\_account\_event\_rule\_name) | Name of the EventBridge rule used for account event syncs. | `string` | `"organizations-account-inventory-account-events"` | no |
| <a name="input_cloudwatch_logs_kms_key_id"></a> [cloudwatch\_logs\_kms\_key\_id](#input\_cloudwatch\_logs\_kms\_key\_id) | The KMS key ID to encrypt CloudWatch Logs. If not provided, logs will not be encrypted. | `string` | `null` | no |
| <a name="input_cloudwatch_logs_log_group_class"></a> [cloudwatch\_logs\_log\_group\_class](#input\_cloudwatch\_logs\_log\_group\_class) | The log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT\_ACCESS. | `string` | `"STANDARD"` | no |
| <a name="input_cloudwatch_logs_retention_in_days"></a> [cloudwatch\_logs\_retention\_in\_days](#input\_cloudwatch\_logs\_retention\_in\_days) | The number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827. | `number` | `7` | no |
| <a name="input_enable_account_event_sync"></a> [enable\_account\_event\_sync](#input\_enable\_account\_event\_sync) | Enable an EventBridge rule to trigger the sync on account creation/closure events. | `bool` | `false` | no |
| <a name="input_enable_scheduled_sync"></a> [enable\_scheduled\_sync](#input\_enable\_scheduled\_sync) | Enable a scheduled EventBridge rule to trigger the sync periodically. | `bool` | `true` | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function to synchronize AWS Organizations account information. | `string` | `"Synchronizes AWS Organizations account information to DynamoDB."` | no |
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
|------|-------------|
| <a name="output_lambda_arn"></a> [lambda\_arn](#output\_lambda\_arn) | The ARN of the Lambda function for tagging compliance. |
| <a name="output_lambda_name"></a> [lambda\_name](#output\_lambda\_name) | The name of the Lambda function for tagging compliance. |
<!-- END_TF_DOCS -->