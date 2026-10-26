# Basic Example

## Description

This example demonstrates the simplest deployment of the tagging compliance
framework. It creates an S3 bucket with a YAML tagging policy that defines
organization-wide tagging rules.

## What This Example Creates

- **S3 Bucket (Policy Repository)**: A bucket named `tagging-compliance` with:
  - YAML tagging policy defining compliance rules
  - Resource type mappings (Terraform to AWS Config types)
  - Versioning enabled
  - Encryption at rest (AES256)
  - Organization-wide read access (when enable_organizations is true)

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
- Permissions to create S3 buckets and bucket policies

## When to Use This Example

Use this basic example when:
- You want to centrally define tagging rules in a YAML policy
- You need an S3 bucket to store the policy for org-wide enforcement
- You're setting up the foundation for tagging compliance

## Next Steps

After deploying this example:

1. **Deploy Config Rules**: Use the `modules/config` module in each account
2. **Or Use Conformance Packs**: Use the `modules/pack` module for org-wide
3. **Update Policy**: Edit `tagging-policy.yaml` and run `terraform apply`

## Customization

To customize this example:

```hcl
module "tagging" {
  source = "../../"

  # Your YAML policy file
  policy = file("${path.module}/tagging-policy.yaml")

  # S3 bucket configuration
  bucket = {
    name          = "my-tagging-compliance"
    kms_key_arn   = aws_kms_key.policy.arn  # Optional: customer key
    force_destroy = true
  }

  # Enable organization access
  enable_organizations = true
  organizations_id     = "o-123456789"

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

**Warning**: This will delete the S3 bucket and all policy versions.

<!-- BEGIN_TF_DOCS -->
## Providers

No providers.

## Inputs

No inputs.

## Outputs

No outputs.
<!-- END_TF_DOCS -->
