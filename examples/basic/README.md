# Basic Example

## Description

This example demonstrates the simplest possible deployment of the tagging compliance framework. It creates only the central DynamoDB table that will store tagging compliance rules.

This is typically the first step in setting up the framework - creating the central rules repository before deploying the evaluation infrastructure (Lambda functions, Config rules, etc.) in subsequent steps.

## What This Example Creates

- **DynamoDB Table**: A table named `tagging-compliance` with:
  - `PAY_PER_REQUEST` billing mode (no capacity planning required)
  - `ResourceType` as the hash key
  - Organization-wide read access policy (if organization_id is provided)
  - Encryption at rest using AWS-managed keys

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

Use this basic example when:
- You're just getting started with the tagging compliance framework
- You want to set up the central rules table before configuring Lambda functions and Config rules
- You need a standalone DynamoDB table for storing compliance rules
- You're testing the module in a development environment

## Next Steps

After deploying this example:

1. **Add Compliance Rules**: Use the `modules/compliance` module to populate the table with tagging rules
2. **Deploy Lambda Evaluator**: Use the `modules/validation` module to create the Lambda function that evaluates resources
3. **Create Config Rules**: Use the `modules/config` module to set up AWS Config rules in each account
4. **Or Use Conformance Packs**: Use the `modules/pack` module for organization-wide deployment

See the `compliance` example for a more complete setup with rules.

## Customization

To customize this example:

```hcl
module "compliance" {
  source = "../../"

  dynamodb_table_name   = "my-custom-table-name"
  dynamodb_billing_mode = "PROVISIONED"  # If you prefer provisioned capacity
  organization_id       = "o-abc123def"  # Your AWS Organization ID

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Purpose     = "tagging-compliance"
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

No providers.

## Inputs

No inputs.

## Outputs

No outputs.
<!-- END_TF_DOCS -->
