# Compliance Rules Example

## Description

This example demonstrates how to create a DynamoDB table and populate it with tagging compliance rules. It shows the complete setup for defining and storing compliance rules that will be evaluated by AWS Config.

This is a more complete example than the basic example, as it includes actual compliance rules that enforce tagging standards across your AWS resources.

## What This Example Creates

1. **DynamoDB Table**: Central rules repository
2. **Compliance Rules**: Two example tagging rules:
   - **EC2 Environment Tag**: Requires all EC2 resources to have an `Environment` tag with values: `Production`, `Staging`, or `Development`
   - **S3 Data Classification Tag**: Requires all S3 resources to have a `DataClassification` tag with values: `Public`, `Private`, or `Confidential`

## Compliance Rules Configuration

```hcl
rules = [
  {
    RuleId       = "ec2-environment-tag-compliance"
    ResourceType = "AWS::EC2::*"              # Applies to all EC2 resources
    Tag          = "Environment"
    Enabled      = true
    Required     = true                       # Tag must be present
    Values       = ["Production", "Staging", "Development"]
    AccountIds   = ["*"]                      # Applies to all accounts
  },
  {
    RuleId       = "s3-data-classification-tag-compliance"
    ResourceType = "AWS::S3::*"               # Applies to all S3 resources
    Tag          = "DataClassification"
    Enabled      = true
    Required     = true
    Values       = ["Public", "Private", "Confidential"]
    AccountIds   = ["*"]
  }
]
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
- Permissions to:
  - Create DynamoDB tables and items
  - Create resource policies

## When to Use This Example

Use this compliance rules example when:
- You want to see a complete setup with actual rules defined
- You're ready to populate your rules table with organizational tagging standards
- You need examples of rule definitions to adapt for your use case
- You want to test rule evaluation in a development environment

## Rule Definition Examples

### Required Tag with Specific Values
```hcl
{
  RuleId       = "require-owner-tag"
  ResourceType = "AWS::*"                    # All resource types
  Tag          = "Owner"
  Required     = true                        # Must be present
  Values       = ["team-a", "team-b", "team-c"]
  AccountIds   = ["*"]
}
```

### Optional Tag (Validate Only If Present)
```hcl
{
  RuleId       = "optional-cost-center"
  ResourceType = "AWS::RDS::DBInstance"
  Tag          = "CostCenter"
  Required     = false                       # Optional
  Values       = ["CC-001", "CC-002", "CC-003"]
  AccountIds   = ["123456789012"]
}
```

### Pattern-Based Validation (Regex)
```hcl
{
  RuleId       = "email-owner-tag"
  ResourceType = "AWS::*"
  Tag          = "Owner"
  Required     = true
  ValuePattern = "^[a-zA-Z0-9._%+-]+@company\\.com$"  # Email format
  AccountIds   = ["*"]
}
```

### Account-Specific Rules
```hcl
{
  RuleId       = "prod-backup-tag"
  ResourceType = "AWS::RDS::DBInstance"
  Tag          = "BackupSchedule"
  Required     = true
  Values       = ["daily", "weekly"]
  AccountIds   = ["111222333444"]            # Production account only
}
```

## Next Steps

After deploying this example:

1. **Review the Rules**: Check the DynamoDB table to see the stored rules
2. **Deploy Lambda Evaluator**: Use `modules/validation` to create the evaluation function
3. **Create Config Rules**: Use `modules/config` to enable compliance checking
4. **View Compliance**: Check AWS Config console for compliance status

## Customizing Rules

To add your own rules, modify the `rules` list in `main.tf`:

```hcl
module "compliance" {
  source = "../../modules/compliance"

  dynamodb_table_name = "tagging-compliance"

  rules = [
    # Your custom rules here
    {
      RuleId       = "my-custom-rule"
      ResourceType = "AWS::Lambda::Function"
      Tag          = "Application"
      Required     = true
      Values       = ["app1", "app2", "app3"]
      AccountIds   = ["*"]
    }
  ]
}
```

## Rule Fields Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `RuleId` | string | Yes | — | Unique identifier for the rule |
| `ResourceType` | string | Yes | — | AWS resource type (e.g., `AWS::EC2::*`) |
| `Tag` | string | Yes | — | Tag key to evaluate |
| `Enabled` | bool | No | `true` | Whether the rule is active |
| `Required` | bool | No | `true` | Whether the tag must be present |
| `Values` | list(string) | No | `[]` | Allowed tag values (if specified) |
| `ValuePattern` | string | No | `""` | Regex pattern for validation |
| `AccountIds` | list(string) | No | `["*"]` | Target AWS account IDs |

## Viewing Rules in DynamoDB

After applying, view your rules:

```bash
# List all rules
aws dynamodb scan --table-name tagging-compliance

# Get a specific rule
aws dynamodb get-item \
  --table-name tagging-compliance \
  --key '{"RuleId": {"S": "ec2-environment-tag-compliance"}, "ResourceType": {"S": "AWS::EC2::*"}}'
```

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

No inputs.

## Outputs

No outputs.
<!-- END_TF_DOCS -->
