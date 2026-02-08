# Organizations Example

## Description

This example demonstrates deployment of the tagging compliance framework with AWS Organizations integration enabled. It creates both the compliance rules table and an organizations metadata table, plus provisions a Lambda function to automatically synchronize AWS account organizational structure.

This example is ideal for enterprise deployments where you want to scope tagging rules based on organizational unit (OU) paths within your AWS Organization.

## What This Example Creates

- **DynamoDB Table (Compliance)**: A table named `tagging-compliance` with:
  - `PAY_PER_REQUEST` billing mode (no capacity planning required)
  - `ResourceType` and `RuleId` as composite key
  - Organization-wide read access policy
  - Encryption at rest using AWS-managed keys

- **DynamoDB Table (Organizations)**: A table named `organizational-accounts` with:
  - Stores account ID, OU path, and metadata for all accounts in the organization
  - `PAY_PER_REQUEST` billing mode
  - `AccountId` as the hash key
  - Organization-wide read access policy

- **Lambda Function (Organizations Handler)**: Automatically syncs AWS Organizations account structure to DynamoDB
- **Compliance Rules**: Example EC2 and S3 tagging rules stored in DynamoDB

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
- Permissions to create DynamoDB tables and resource policies

## When to Use This Example

Use this organizations example when:
- You have an AWS Organization with multiple accounts
- You want to scope tagging rules based on organizational unit (OU) paths
- You need to track which account belongs to which OU for compliance reporting
- You want rules to automatically apply based on an account's position in the organization hierarchy
- You're deploying in an enterprise environment with structured account management

## Next Steps

After deploying this example:

1. **Add Compliance Rules**: Use the `modules/compliance` module to populate the table with tagging rules
2. **Deploy Lambda Evaluator**: Use the `modules/validation` module to create the Lambda function that evaluates resources
3. **Create Config Rules**: Use the `modules/config` module to set up AWS Config rules in each account
4. **Or Use Conformance Packs**: Use the `modules/pack` module for organization-wide deployment

See the `compliance` example for a more complete setup with rules.

## Key Features

This example demonstrates:

1. **Organizational Unit Path Scoping**: Rules can target specific OUs (e.g., `/root/workloads/production`)
2. **Automatic Account Discovery**: Lambda function periodically syncs account structure
3. **Centralized Governance**: Single source of truth for both rules and organizational structure
4. **Account Metadata**: Track which accounts belong to which OUs for reporting and automation

## Customization

To customize this example:

```hcl
data "aws_organizations_organization" "current" {}

module "compliance" {
  source = "../../"

  # Enable AWS Organizations integration
  enable_organizations = true
  organizations_id     = data.aws_organizations_organization.current.id

  # Configure the compliance DynamoDB table
  compliance = {
    table = {
      name         = "my-tagging-compliance"
      billing_mode = "PAY_PER_REQUEST"
    }
  }

  # Configure the organizations DynamoDB table and Lambda
  organizations = {
    table = {
      name = "my-org-accounts"
    }
    lambda = {
      name        = "org-account-sync"
      description = "Syncs AWS Organizations account structure"
      log_level   = "INFO"
      timeout     = 60
    }
  }

  # Add your own compliance rules
  rules = [
    {
      RuleId              = "prod-cost-center"
      ResourceType        = "AWS::*"
      Tag                 = "CostCenter"
      Required            = true
      ValuePattern        = "^CC-[0-9]{4}$"
      OrganizationalPaths = ["/root/workloads/production"]  # Only prod OU
    }
  ]

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
  }
}
```

## Cleanup

To destroy all resources created by this example:

```bash
terraform destroy
```

**Warning**: This will delete the DynamoDB table and all compliance rules stored in it.

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_dynamodb_table_arn"></a> [dynamodb\_table\_arn](#output\_dynamodb\_table\_arn) | The ARN of the DynamoDB table used for tagging compliance. |
| <a name="output_organizations_table_arn"></a> [organizations\_table\_arn](#output\_organizations\_table\_arn) | The ARN of the DynamoDB table used for storing organization metadata. |
<!-- END_TF_DOCS -->
