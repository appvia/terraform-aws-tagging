# Organizations Example

## Description

This example demonstrates deployment of the tagging compliance framework with AWS Organizations integration enabled. It creates an S3 bucket with the YAML tagging policy, resource type mappings, and account inventory, plus provisions organization-wide conformance pack deployment and a Lambda function to automatically synchronize AWS account organizational structure.

This example is ideal for enterprise deployments where you want to scope tagging rules based on organizational unit (OU) paths, account IDs, or account tags within your AWS Organization.

## What This Example Creates

- **S3 Bucket (Policy Repository)**: A bucket named `tagging-compliance-org` with:
  - YAML tagging policy with organizational rules
  - Resource type mappings (Terraform to AWS Config types)
  - Account inventory with tags (written by organizations Lambda)
  - Organization-wide read access policy
  - Versioning enabled
  - Encryption at rest (AES256 or KMS)

- **Organizations Lambda**: Automatically syncs AWS Organizations account structure and tags to S3 as `accounts.yaml`
  - Triggers on account create, close, move, tag changes (via EventBridge in us-east-1)
  - Daily scheduled sync
  - Re-puts conformance pack to trigger re-evaluation when inventory changes

- **Organization Conformance Pack**: Deploys Config rules to all accounts in the organization

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
- AWS Organizations management account or delegated administrator
- Permissions to create S3 buckets, Lambda functions, organization conformance packs

## When to Use This Example

Use this organizations example when:
- You have an AWS Organization with multiple accounts
- You want to scope tagging rules based on organizational unit (OU) paths, account IDs, or account tags
- You need automatic re-evaluation when accounts move between OUs or account tags change
- You want organization-wide deployment via conformance packs
- You're deploying in an enterprise environment with structured account management

## Next Steps

After deploying this example:

1. **Bootstrap**: On first apply, `inventory_version = "none"` and conformance pack references are commented out (see inline comments)
2. **Second Apply**: After first apply succeeds, uncomment the conformance pack references in the organizations block to enable automatic re-evaluation
3. **Update Policy**: Edit `tagging-policy.yaml` and run `terraform apply` - changes trigger org-wide re-evaluation
4. **Monitor**: Use AWS Config console to view compliance status across all accounts

## Key Features

This example demonstrates:

1. **Organizational Path Filtering**: Rules can target specific OUs (e.g., `root/Production` matches that OU and children)
2. **Account ID Filtering**: Rules can target specific accounts by ID
3. **Account Tag Filtering**: Rules can filter based on account-level tags (e.g., `Billable: "true"`)
4. **Mixed Resource Types**: Combine Terraform names (`aws_s3_bucket`) and AWS Config types (`AWS::DynamoDB::Table`) in one rule
5. **Automatic Re-evaluation**: Policy, mappings, and inventory changes trigger org-wide re-evaluation
6. **Account Inventory**: Lambda syncs account structure and tags to S3 on events and daily schedule

## Customization

To customize this example:

```hcl
data "aws_organizations_organization" "current" {}

module "tagging" {
  source = "../../"

  # Your YAML policy file
  policy = file("${path.module}/tagging-policy.yaml")

  # S3 bucket configuration
  bucket = {
    name        = "my-tagging-compliance"
    kms_key_arn = aws_kms_key.policy.arn  # Optional: use customer-managed key
  }

  # Enable AWS Organizations integration
  enable_organizations = true
  organizations_id     = data.aws_organizations_organization.current.id

  # Configure the organizations Lambda
  organizations = {
    conformance_pack_name         = "my-tagging-pack"
    conformance_pack_template_uri = module.pack.s3_template_uri
    enable_account_event_sync     = true
    lambda = {
      name      = "my-org-inventory"
      log_level = "INFO"
    }
  }

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
  }
}

module "pack" {
  source = "../../modules/pack"

  policy_bucket_name = module.tagging.bucket_name
  policy_bucket_arn  = module.tagging.bucket_arn
  policy_key         = module.tagging.policy_key
  policy_version     = module.tagging.policy_version
  mappings_key       = module.tagging.mappings_key
  mappings_version   = module.tagging.mappings_version
  accounts_key       = module.tagging.accounts_key
  kms_key_arn        = module.tagging.kms_key_arn

  s3_bucket_name           = "my-pack-templates"
  conformance_pack_name    = "my-tagging-pack"
  deploy_organization_wide = true
}
```

## Cleanup

To destroy all resources created by this example:

```bash
terraform destroy
```

**Warning**: This will delete the S3 bucket, all policy versions, and the account inventory.

<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0.0 |

## Inputs

No inputs.

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_bucket_arn"></a> [bucket\_arn](#output\_bucket\_arn) | The ARN of the S3 bucket holding the tagging policy |
| <a name="output_bucket_name"></a> [bucket\_name](#output\_bucket\_name) | The name of the S3 bucket holding the tagging policy |
| <a name="output_conformance_pack_name"></a> [conformance\_pack\_name](#output\_conformance\_pack\_name) | The name of the organization conformance pack |
| <a name="output_policy_key"></a> [policy\_key](#output\_policy\_key) | The S3 object key of the tagging policy |
<!-- END_TF_DOCS -->
