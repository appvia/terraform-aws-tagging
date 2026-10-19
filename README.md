![Github Actions](https://github.com/appvia/terraform-aws-tagging/actions/workflows/terraform.yml/badge.svg)

# Terraform AWS Tagging Compliance Framework

## Description

A comprehensive framework for enforcing tagging compliance across AWS Organizations using centralized rule management and AWS Config custom rules. This solution enables platform teams to define tagging standards once and enforce them consistently across all accounts in an organization.

### Architecture Overview

The framework supports two deployment patterns:

#### Pattern 1: Per-Account Config Rules (Traditional)
```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Account                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  S3 Bucket (Policy Repository)                           │  │
│  │  • policy.yaml (YAML tagging rules)                      │  │
│  │  • mappings.yaml (Terraform → Config types)              │  │
│  │  • accounts.yaml (inventory, optional)                   │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-account Read Access                │
└──────────────────────┼───────────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Account A  │ │  Account B  │ │  Account C  │
│             │ │             │ │             │
│  AWS Config │ │  AWS Config │ │  AWS Config │
│     Rule    │ │     Rule    │ │     Rule    │
│      ↓      │ │      ↓      │ │      ↓      │
│   Lambda    │ │   Lambda    │ │   Lambda    │
│  (reads S3) │ │  (reads S3) │ │  (reads S3) │
│      ↓      │ │      ↓      │ │      ↓      │
│  Evaluates  │ │  Evaluates  │ │  Evaluates  │
│   Policy    │ │   Policy    │ │   Policy    │
└─────────────┘ └─────────────┘ └─────────────┘
```

#### Pattern 2: Organization Conformance Pack (Recommended)
```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Account                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  S3 Bucket (Policy Repository)                           │  │
│  │  • policy.yaml (YAML tagging rules)                      │  │
│  │  • mappings.yaml (Terraform → Config types)              │  │
│  │  • accounts.yaml (inventory with tags)                   │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │ Cross-account Read Access                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Organizations Lambda                                     │  │
│  │  • Syncs account inventory to S3                         │  │
│  │  • Triggers on account/OU/tag changes                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Pack S3 Bucket                                           │  │
│  │  • conformance-pack.yaml template                        │  │
│  │  • Versioning enabled                                    │  │
│  │  • Encrypted                                             │  │
│  └───────────────────┬──────────────────────────────────────┘  │
│                      │                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Organization Conformance Pack                            │  │
│  │  Deploys Config rules to all accounts                    │  │
│  └───────────────────┬──────────────────────────────────────┘  │
└──────────────────────┼───────────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Account A  │ │  Account B  │ │  Account C  │
│             │ │             │ │             │
│ Config Rule │ │ Config Rule │ │ Config Rule │
│      ↓      │ │      ↓      │ │      ↓      │
│   Lambda    │ │   Lambda    │ │   Lambda    │
│  (reads S3) │ │  (reads S3) │ │  (reads S3) │
│      ↓      │ │      ↓      │ │      ↓      │
│  Evaluates  │ │  Evaluates  │ │  Evaluates  │
│   Policy    │ │   Policy    │ │   Policy    │
└─────────────┘ └─────────────┘ └─────────────┘
```

### How It Works

1. **YAML Policy Definition**: Tagging compliance rules are defined once in a YAML policy file stored in S3 (typically in the management or shared services account)
2. **Organization-Wide Access**: The S3 bucket has a policy allowing read access from all accounts in the AWS Organization
3. **Per-Account Enforcement**: Each account deploys an AWS Config custom rule with a Lambda function (via per-account rules or organization conformance pack)
4. **Real-Time Validation**: When resources are created or modified, AWS Config invokes the Lambda function
5. **Compliance Evaluation**: The Lambda loads the policy from S3 (with caching and ETag revalidation) and evaluates the resource's tags against the rules
6. **Reporting**: Compliance status is reported back to AWS Config, providing visibility in the AWS Console and enabling automated remediation
7. **Automatic Re-evaluation**: Policy changes trigger Config to re-evaluate all resources via version hash parameters; inventory changes (account moves, tag updates) trigger re-evaluation via the organizations Lambda

### Key Features

- **Centralized Management**: Define tagging rules once, enforce everywhere
- **Organization-Wide Scope**: Works across all accounts in an AWS Organization
- **Flexible Rules**: Support for required/optional tags, permitted values, and regex patterns
- **Organizational Path Scoping**: Target rules to specific AWS Organizations paths (e.g. `root/Sandbox`)
- **Account Scoping**: Apply different rules to different accounts (e.g., stricter rules for production)
- **Resource Type Filtering**: Target specific AWS services or resource types
- **Real-Time Enforcement**: Automatic evaluation when resources change
- **Easy Updates**: Change rules centrally without redeploying to each account
- **Compliance Reporting**: View compliance status in AWS Config console
- **Infrastructure as Code**: Fully managed through Terraform

## Modules

This framework consists of four modular components:

### 1. Root Module (This Module)
Provisions the S3 bucket with the tagging policy, resource type mappings, and optional account inventory. Deploy this in your management or shared services account.

**[Documentation](./README.md)**

### 2. Validation Module
Contains the Lambda function that evaluates resource compliance against the YAML policy. Includes the policy parser, evaluation engine, and S3 caching layer. Automatically used by Config and Pack modules.

**[📖 Validation Module Documentation](./modules/validation/README.md)**

### 3. Config Module
Deploys AWS Config custom rules in individual accounts with a validation Lambda. Reads the policy, mappings, and inventory from the S3 bucket created by the root module.

**[📖 Config Module Documentation](./modules/config/README.md)**

### 4. Pack Module
Wraps the validation Lambda into an AWS Config Conformance Pack for organization-wide distribution. Handles S3 template storage, versioning, and deployment via Organizations. Automatically re-evaluates on policy and inventory changes.

**[📖 Pack Module Documentation](./modules/pack/README.md)**

## Prerequisites

- Terraform >= 1.3.0 and the AWS provider >= 6.0.0
- **Lambda build host**: the validation and organizations Lambdas are packaged with their
  `requirements.txt` (`pip_requirements = true`), so the machine running `terraform plan`/`apply`
  needs, on its `PATH`, a Python interpreter matching each Lambda runtime (`python3.14` for the
  validation Lambda, `python3.12` for the organizations Lambda by default) with `pip`, and network
  access to PyPI. To build with a different interpreter, override the runtime: `lambda_runtime` on
  the config module (or validation module) and `organizations.lambda.runtime` on the root module.

## Usage

### Step 1: Deploy S3 Policy Bucket (Management Account)

Create the S3 bucket with your YAML tagging policy. If you use organizational
path or account tag filters, enable the organizations Lambda to maintain the
account inventory.

```hcl
# In your management account (or shared services account)
module "tagging_compliance_central" {
  source  = "appvia/tagging/aws"
  version = "2.0.0"

  # Your YAML tagging policy
  policy = file("${path.module}/tagging-policy.yaml")

  # S3 bucket configuration
  bucket = {
    name = "org-tagging-compliance"
  }

  # Enable organization-wide access
  enable_organizations = true
  organizations_id     = "o-123456789"  # Your AWS Organization ID

  # Enable organizations inventory for OU/account-tag filtering (optional)
  organizations = {
    lambda = {
      name = "org-account-inventory"
    }
  }

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
  }
}

output "policy_bucket_name" {
  value       = module.tagging_compliance_central.bucket_name
  description = "Name of the S3 bucket holding the tagging policy"
}
```

Example `tagging-policy.yaml`:

```yaml
version: 1
rules:
  - name: require-environment-tag
    description: All resources must have Environment tag
    steps:
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [production, staging, development]}

  - name: require-owner-email
    description: All resources must have Owner email
    steps:
      - assert: {tag: Owner, present: true}
      - assert: {tag: Owner, matches: "^[a-zA-Z0-9._%+-]+@company\\.com$"}

  - name: prod-cost-center
    description: Production resources require CostCenter
    steps:
      - filter: {account_id: ["111222333444"]}
      - assert: {tag: CostCenter, present: true}
      - assert: {tag: CostCenter, matches: "^CC-[0-9]{4}$"}

  - name: sandbox-owner-requirement
    description: Sandbox OU resources require Owner
    steps:
      - filter: {organizational_path: root/Sandbox}
      - assert: {tag: Owner, present: true}
```

Validate your policy before deploying:

```bash
python3 modules/validation/assets/policy.py tagging-policy.yaml
```

### Step 2: Deploy Config Rules (Each Account)

```hcl
# In each member account that should enforce compliance
module "tagging_compliance_evaluator" {
  source  = "appvia/tagging/aws//modules/config"
  version = "2.0.0"

  # Reference the central S3 policy bucket (cross-account)
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "<policy-sha256>"  # From root module output
  mappings_key       = "mappings.yaml"
  mappings_version   = "<mappings-sha256>"  # From root module output
  accounts_key       = "accounts.yaml"

  # Lambda configuration
  lambda_name        = "tagging-compliance-evaluator"
  lambda_log_level   = "INFO"

  # AWS Config rule configuration
  config_name           = "tagging-compliance"
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function"
  ]

  # CloudWatch Logs
  cloudwatch_logs_retention_in_days = 14

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Step 3: Update Policy (Anytime)

Edit your `tagging-policy.yaml` and run `terraform apply`. Policy changes
trigger AWS Config to re-evaluate all resources via the version hash
parameters.

```yaml
# Add a new rule to tagging-policy.yaml
- name: s3-data-classification
  description: S3 buckets must declare data classification
  steps:
    - filter: {type: aws_s3_bucket}
    - assert: {tag: DataClassification, present: true}
    - assert: {tag: DataClassification, in: [Public, Internal, Confidential]}
```

Then apply:

```bash
# Validate the policy first
python3 modules/validation/assets/policy.py tagging-policy.yaml

# Apply the change
terraform apply
```

## Complete Multi-Account Example

Here's a complete example showing deployment across a typical AWS Organization:

### Management Account (`management-account/tagging.tf`)

```hcl
# Create S3 bucket with YAML tagging policy
module "tagging_compliance" {
  source = "appvia/tagging/aws"

  # The YAML tagging policy
  policy = file("${path.module}/tagging-policy.yaml")

  # S3 bucket configuration
  bucket = {
    name = "org-tagging-compliance"
  }

  # Enable organization-wide access
  enable_organizations = true
  organizations_id     = data.aws_organizations_organization.current.id

  # Enable inventory for OU/account-tag filtering
  organizations = {
    lambda = {
      name = "org-account-inventory"
    }
  }

  tags = {
    Environment = "management"
    ManagedBy   = "terraform"
    Purpose     = "tagging-compliance"
  }
}

output "policy_bucket_name" {
  value       = module.tagging_compliance.bucket_name
  description = "Name of the S3 bucket holding the tagging policy"
}

output "policy_version" {
  value       = module.tagging_compliance.policy_version
  description = "SHA256 of the tagging policy"
}
```

Example `tagging-policy.yaml`:

```yaml
version: 1
rules:
  # Global rules for all accounts
  - name: global-environment-tag
    description: All resources must have Environment tag
    steps:
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [production, staging, development]}

  - name: global-owner-tag
    description: All resources must have Owner email
    steps:
      - assert: {tag: Owner, present: true}
      - assert: {tag: Owner, matches: "^[a-zA-Z0-9._%+-]+@company\\.com$"}

  - name: global-managed-by-tag
    description: All resources must have ManagedBy tag
    steps:
      - assert: {tag: ManagedBy, present: true}
      - assert: {tag: ManagedBy, in: [terraform, cloudformation, console]}

  # Production-specific rules
  - name: prod-cost-center
    description: Production resources require CostCenter
    steps:
      - filter: {account_id: ["111222333444"]}
      - assert: {tag: CostCenter, present: true}
      - assert: {tag: CostCenter, matches: "^CC-[0-9]{4}$"}

  - name: prod-compliance
    description: Production resources require Compliance tag
    steps:
      - filter: {account_id: ["111222333444"]}
      - assert: {tag: Compliance, present: true}
      - assert: {tag: Compliance, in: [sox, pci, hipaa, none]}
```

### Production Account (`production-account/config-rules.tf`)

```hcl
# Deploy AWS Config rule to enforce compliance in production account
module "tagging_evaluator" {
  source = "appvia/tagging/aws//modules/config"

  # Reference the central S3 policy bucket
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."  # From management account output
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."  # From management account output
  accounts_key       = "accounts.yaml"

  lambda_name      = "tagging-compliance-prod"
  lambda_log_level = "INFO"
  lambda_timeout   = 60

  config_name           = "tagging-compliance-prod"
  config_resource_types = [
    "AWS::EC2::Instance",
    "AWS::EC2::Volume",
    "AWS::EC2::SecurityGroup",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::Lambda::Function",
    "AWS::DynamoDB::Table",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service"
  ]

  cloudwatch_logs_retention_in_days = 30  # Longer retention for production
  cloudwatch_logs_kms_key_id        = aws_kms_key.logs.id

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Development Account (`development-account/config-rules.tf`)

```hcl
# Deploy AWS Config rule to enforce compliance in development account
module "tagging_evaluator" {
  source = "appvia/tagging/aws//modules/config"

  # Reference the central S3 policy bucket
  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."  # From management account output
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."  # From management account output
  accounts_key       = "accounts.yaml"

  lambda_name      = "tagging-compliance-dev"
  lambda_log_level = "DEBUG"  # More verbose logging in dev

  config_name           = "tagging-compliance-dev"
  config_resource_types = ["*"]  # Evaluate all resource types

  cloudwatch_logs_retention_in_days = 7  # Shorter retention for dev

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
```

## Rule Examples

Each example is a complete policy file; check one with
`python3 modules/validation/assets/policy.py tagging-policy.yaml`. Combine rules under a single
`rules:` list in your own policy.

### Basic Required Tags

```yaml
version: 1
rules:
  - name: require-environment
    description: EC2 instances must carry a valid Environment tag
    steps:
      - filter: {type: aws_instance}
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [production, staging, development]}
```

### Email Pattern Validation

```yaml
version: 1
rules:
  - name: validate-owner-email
    description: Every resource must have an Owner tag holding a company email address
    steps:
      - assert: {tag: Owner, present: true}
      - assert: {tag: Owner, matches: '^[a-zA-Z0-9._%+-]+@(company\.com|partner\.com)$'}
```

### Account-Specific Rules

```yaml
version: 1
rules:
  - name: prod-cost-tracking
    description: Production accounts must tag resources with a cost centre
    steps:
      - filter: {account_id: ["111222333444", "555666777888"]}
      - assert: {tag: CostCenter, matches: '^CC-[0-9]{4}$'}
  - name: production-ou-owner
    description: Accounts under the Production OU (needs the account inventory)
    steps:
      - filter: {organizational_path: root/Production}
      - assert: {tag: Owner, present: true}
```

### Optional Tags

A filter on the tag being present makes the rule apply only to resources that carry it:

```yaml
version: 1
rules:
  - name: optional-project
    description: When set, the Project tag must be a known project
    steps:
      - filter: {type: aws_lambda_function}
      - filter: {tag: Project, present: true}
      - assert: {tag: Project, in: [web-app, api, data-pipeline]}
```

## Monitoring and Compliance

### View Compliance in AWS Console

1. Navigate to **AWS Config** in each account
2. Go to **Rules** → **tagging-compliance**
3. View compliant and non-compliant resources
4. Click on resources to see detailed evaluation results

### Query with CloudWatch Logs Insights

```
fields @timestamp, compliance_type, resource_type, resource_id
| filter action = "lambda_handler"
| stats count() by compliance_type, resource_type
| sort count desc
```

### AWS CLI Commands

```bash
# Check rule compliance status
aws configservice describe-compliance-by-config-rule \
  --config-rule-names tagging-compliance

# Get non-compliant resources
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name tagging-compliance \
  --compliance-types NON_COMPLIANT

# Evaluate a specific resource
aws configservice get-resource-config-history \
  --resource-type AWS::EC2::Instance \
  --resource-id i-1234567890abcdef0
```

## Deployment Patterns

### Pattern 1: Individual Config Rules Per Account (Traditional)

Each account deploys its own Config rules via the `config` module:

```hcl
# In each member account
module "tagging_config" {
  source = "appvia/tagging/aws//modules/config"

  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."
  accounts_key       = "accounts.yaml"

  lambda_name = "org-tagging-compliance"
  config_name = "tagging-compliance"

  tags = { Environment = "production" }
}
```

**Pros:**
- Fine-grained control per account
- Can customize rules per account
- Easier troubleshooting per account

**Cons:**
- Must deploy to each account separately
- More Terraform state management

### Pattern 2: Organization Conformance Pack (Recommended)

Use the `pack` module to deploy organization-wide via CloudFormation StackSet:

```hcl
# In management account
module "tagging_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance"
  s3_bucket_name           = "org-pack-templates"
  deploy_organization_wide = true

  policy_bucket_name = module.tagging_central.bucket_name
  policy_bucket_arn  = module.tagging_central.bucket_arn
  policy_key         = module.tagging_central.policy_key
  policy_version     = module.tagging_central.policy_version
  mappings_key       = module.tagging_central.mappings_key
  mappings_version   = module.tagging_central.mappings_version
  accounts_key       = module.tagging_central.accounts_key

  excluded_accounts = ["111111111111"]  # Sandbox accounts

  tags = { Environment = "management" }
}
```

**Pros:**
- Single deployment for entire organization
- Automatic deployment to new accounts
- Centralized version control via S3
- Self-service compliance for business units

**Cons:**
- Less granular control per account
- Requires AWS Organizations

### Pattern 3: Hybrid Approach

Use pack for most accounts, individual config rules for special cases:

```hcl
# Management account
module "tagging_pack" {
  source = "appvia/tagging/aws//modules/pack"

  conformance_pack_name    = "org-tagging-compliance"
  s3_bucket_name           = "org-conformance-packs"
  deploy_organization_wide = true
  excluded_accounts        = ["111111111111", "222222222222"]  # Custom configs

  # ... other config
}

# Production account (custom config)
module "tagging_config_prod" {
  source = "appvia/tagging/aws//modules/config"

  policy_bucket_name = "org-tagging-compliance"
  policy_bucket_arn  = "arn:aws:s3:::org-tagging-compliance"
  policy_key         = "policy.yaml"
  policy_version     = "abc123..."
  mappings_key       = "mappings.yaml"
  mappings_version   = "def456..."
  accounts_key       = "accounts.yaml"

  lambda_name = "org-tagging-compliance"
  config_name = "tagging-compliance-prod"

  # ... other config
}
```

## Best Practices

1. **Start with Observability**: Use `severity: warning` on new rules initially; violations are logged but resources stay COMPLIANT
2. **Test in Non-Production**: Validate rules in dev/test accounts before production
3. **Use Descriptive Rule Names**: Make rules easy to identify (e.g., `name: prod-require-cost-center`) and fill in `description`
4. **Document Patterns**: Add YAML comments explaining complex `matches` regular expressions
5. **Version Control**: Store Terraform code in Git for audit trail
6. **Gradual Enablement**: Enable rules incrementally to avoid overwhelming teams
7. **Monitor Compliance**: Set up dashboards and alerts for compliance metrics
8. **Regular Reviews**: Periodically review and update rules as requirements change
9. **Account Scoping**: Use stricter rules in production accounts
10. **Automated Remediation**: Consider building automated remediation for common violations

## Troubleshooting

### Lambda Function Errors

Check CloudWatch Logs for the Lambda function:
```bash
aws logs tail /aws/lambda/tagging-compliance-evaluator --follow
```

### S3 Access Issues

Verify the bucket policy allows cross-account access:
```bash
aws s3api get-bucket-policy --bucket org-tagging-compliance
```

Ensure the policy grants `s3:GetObject` to your organization or accounts.

### Config Rule Not Triggering

Check Config recorder status:
```bash
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
```

### Resource Not Evaluated

Verify the resource type is in the Config rule scope:
```bash
aws configservice describe-config-rules --config-rule-names tagging-compliance
```

## Upgrading from DynamoDB

Version 2.0 replaced DynamoDB-based rule storage with a YAML tagging policy stored in S3. This is a breaking change.

### Migration Steps

1. **Export existing DynamoDB rules** to a YAML policy file:

| DynamoDB Attribute | YAML Policy Mapping |
|--------------------|---------------------|
| `Tag` | `assert: {tag: <Tag>, ...}` in a rule's `steps` |
| `Values` (list) | `assert: {tag: <Tag>, in: [<Values>]}` |
| `ValuePattern` (regex) | `assert: {tag: <Tag>, matches: "<ValuePattern>"}` |
| `Required: true` | `assert: {tag: <Tag>, present: true}` |
| `Required: false` | `filter: {tag: <Tag>, present: true}` before assert (optional tags only checked if present) |
| `ResourceTypes` | `filter: {type: [<ResourceTypes>]}` (supports both Terraform names like `aws_s3_bucket` and AWS Config types like `AWS::S3::Bucket`) |
| `AccountIds` | `filter: {account_id: [<AccountIds>]}` (omit wildcards; no filter = all accounts) |
| `OrganizationalPaths` | `filter: {organizational_path: <path>}` (e.g., `root/Production` matches that OU and children) |

Example conversion:
```yaml
# DynamoDB rule:
# { RuleId: "s3-env-tag", ResourceTypes: ["AWS::S3::*"], Tag: "Environment",
#   Values: ["Production", "Development"], Required: true, AccountIds: ["*"] }

# YAML policy:
version: 1
rules:
  - name: s3-env-tag
    description: S3 buckets must have Environment tag with valid values
    steps:
      - filter: {type: aws_s3_bucket}
      - assert: {tag: Environment, present: true}
      - assert: {tag: Environment, in: [Production, Development]}
```

2. **Validate the policy** with the built-in validator:
```bash
python3 modules/validation/assets/policy.py tagging-policy.yaml
```

3. **Update the root module** configuration:
```hcl
# Before (DynamoDB)
module "tagging" {
  source = "appvia/tagging/aws"
  version = "~> 1.0"

  compliance = {
    table = {
      name = "tagging-compliance"
    }
  }
  rules = [...]  # DynamoDB rules
}

# After (S3 + YAML policy)
module "tagging" {
  source = "appvia/tagging/aws"
  version = "~> 2.0"

  policy = file("${path.module}/tagging-policy.yaml")
  bucket = {
    name = "tagging-compliance"
  }
}
```

4. **Update config/pack modules** to pass the new S3 outputs:
```hcl
# Before
module "config" {
  source = "appvia/tagging/aws//modules/config"
  compliance_rule_table_arn = module.tagging.compliance_rule_table_arn
  # ...
}

# After
module "config" {
  source = "appvia/tagging/aws//modules/config"
  policy_bucket_name = module.tagging.bucket_name
  policy_bucket_arn  = module.tagging.bucket_arn
  policy_key         = module.tagging.policy_key
  policy_version     = module.tagging.policy_version
  mappings_key       = module.tagging.mappings_key
  mappings_version   = module.tagging.mappings_version
  accounts_key       = module.tagging.accounts_key
  kms_key_arn        = module.tagging.kms_key_arn
  # ...
}
```

### Removed Variables and Outputs

**Removed root module variables:**
- `compliance` (object with `table` configuration)
- `rules` (list of DynamoDB rule objects)

**Removed root module outputs:**
- `compliance_rule_table_arn`
- `compliance_rule_table_name`
- `organizations_table_arn`
- `organizations_table_name`

**Removed config/pack module variables:**
- `compliance_rule_table_arn`
- `organizations_table_arn`

### New Features

The YAML policy format adds:
- **Organizational path filtering**: `filter: {organizational_path: root/Production}` matches accounts in that OU subtree
- **Account tag filtering**: `filter: {account_tag: CostCentre, present: true}` requires account-level tags
- **Mixed resource type formats**: `filter: {type: [aws_s3_bucket, AWS::DynamoDB::Table]}` supports both Terraform and Config types in one rule
- **Richer operators**: `contains`, `starts_with`, `ends_with`, `matches` (regex), case operators (`is_kebab`, `is_snake`, etc.)
- **Severity levels**: `severity: warning` (logged, but resource is COMPLIANT) vs `severity: error` (NON_COMPLIANT, the default)

### Resource Type Scope

`mappings.yaml` is also the allowlist of evaluated resource types: a resource whose AWS Config type
is not a value in the mappings is reported NOT_APPLICABLE ("is not taggable"). Resource types that
the DynamoDB rules evaluated but that are missing from the shipped mappings therefore stop being
evaluated after the upgrade. Add them through the root module's `mappings` variable, which is merged
over the shipped file:

```hcl
module "tagging" {
  source = "appvia/tagging/aws"

  policy = file("${path.module}/tagging-policy.yaml")
  mappings = {
    aws_sagemaker_notebook_instance = "AWS::SageMaker::NotebookInstance"
  }
  # ...
}
```

The validation Lambda logs a warning at load time listing Terraform type names used in `type`
conditions or `exclude_resource_types` that are missing from the mappings.

### Known Limitations

- **CI action compatibility**: The `terraform-tag-check` action in `appvia-cicd-workflows` does not yet support `AWS::` types or the new `organizational_path`, `account_id`, `account_tag` targets. Policies using these features will be rejected by the action.
- **Per-account config rules**: Inventory changes (account moves, tag updates) do not automatically trigger re-evaluation for per-account config module rules. Use the pack module (organization conformance pack) for automatic re-evaluation.

## Update Documentation

The `terraform-docs` utility is used to generate this README. Follow the below steps to update:

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
| <a name="input_policy"></a> [policy](#input\_policy) | The tagging policy as YAML content (version: 1), uploaded to the bucket as policy.yaml. Typically file("tagging-policy.yaml"). | `string` | n/a | yes |
| <a name="input_bucket"></a> [bucket](#input\_bucket) | Configuration for the S3 bucket holding the tagging policy, the resource type mappings and the account inventory. | <pre>object({<br/>    ## The name of the S3 bucket to provision.<br/>    name = optional(string, "tagging-compliance")<br/>    ## The ARN of an existing KMS key used to encrypt the bucket (aws:kms). When null, AES256 is used. The module never creates a key.<br/>    kms_key_arn = optional(string)<br/>    ## Whether to delete all objects (including versions) when the bucket is destroyed.<br/>    force_destroy = optional(bool, false)<br/>  })</pre> | `{}` | no |
| <a name="input_enable_organizations"></a> [enable\_organizations](#input\_enable\_organizations) | Enable organization access to the policy bucket. When enabled, allows any account in the organization to read the policy, mappings and inventory. | `bool` | `true` | no |
| <a name="input_mappings"></a> [mappings](#input\_mappings) | Additional Terraform to AWS Config resource type mappings (e.g. aws\_s3\_bucket = "AWS::S3::Bucket"), merged over the shipped mappings file. The mappings also define the taggable resource types. | `map(string)` | `{}` | no |
| <a name="input_organizations"></a> [organizations](#input\_organizations) | Configuration for the organizations inventory lambda. When null, no account inventory is maintained. | <pre>object({<br/>    ## The name of the organization conformance pack to re-put with a new InventoryVersion when the<br/>    ## inventory changes (forces an org-wide re-evaluation). Requires conformance_pack_template_uri.<br/>    conformance_pack_name = optional(string)<br/>    ## The S3 URI (s3://bucket/key) of the conformance pack template. Build it from the values passed<br/>    ## to the pack module's s3_bucket_name and s3_template_key; referencing the pack module output<br/>    ## s3_template_uri creates a dependency cycle, as the pack consumes this module's accounts_key.<br/>    conformance_pack_template_uri = optional(string)<br/>    ## Trigger the sync on account create, close, move, tag and untag events. Organizations CloudTrail<br/>    ## events are delivered to EventBridge only in us-east-1, so the module must be deployed in<br/>    ## us-east-1 for this trigger to fire; elsewhere only the scheduled sync runs.<br/>    enable_account_event_sync = optional(bool, true)<br/>    lambda = optional(object({<br/>      ## The description of the Lambda function to handle AWS Organization account movements.<br/>      description = optional(string, "Handles AWS Organization account movements for tagging compliance.")<br/>      ## The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL.<br/>      log_level = optional(string, "INFO")<br/>      ## The amount of memory in MB allocated to the Lambda function.<br/>      memory_size = optional(number, 128)<br/>      ## The name of the Lambda function to handle AWS Organization account movements.<br/>      name = optional(string, "organization-compliance")<br/>      ## The runtime environment for the Lambda function.<br/>      runtime = optional(string, "python3.12")<br/>      ## The timeout for the Lambda function in seconds.<br/>      timeout = optional(number, 60)<br/>    }), {})<br/>  })</pre> | `null` | no |
| <a name="input_organizations_id"></a> [organizations\_id](#input\_organizations\_id) | AWS Organization ID allowed to read the policy bucket. | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to apply to all resources. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_accounts_key"></a> [accounts\_key](#output\_accounts\_key) | The object key of the account inventory in the policy bucket, or null when organizations is not enabled. |
| <a name="output_bucket_arn"></a> [bucket\_arn](#output\_bucket\_arn) | The ARN of the S3 bucket holding the tagging policy, mappings and inventory. |
| <a name="output_bucket_name"></a> [bucket\_name](#output\_bucket\_name) | The name of the S3 bucket holding the tagging policy, mappings and inventory. |
| <a name="output_kms_key_arn"></a> [kms\_key\_arn](#output\_kms\_key\_arn) | The ARN of the KMS key encrypting the policy bucket, or null when AES256 is used. |
| <a name="output_mappings_key"></a> [mappings\_key](#output\_mappings\_key) | The object key of the resource type mappings in the policy bucket. |
| <a name="output_mappings_version"></a> [mappings\_version](#output\_mappings\_version) | The sha256 of the rendered mappings, used to force re-evaluation when the mappings change. |
| <a name="output_organizations_id"></a> [organizations\_id](#output\_organizations\_id) | The ID of the AWS Organization allowed to read the policy bucket. |
| <a name="output_organizations_lambda_arn"></a> [organizations\_lambda\_arn](#output\_organizations\_lambda\_arn) | The ARN of the Lambda function used for handling organization account movements. |
| <a name="output_organizations_lambda_name"></a> [organizations\_lambda\_name](#output\_organizations\_lambda\_name) | The name of the Lambda function used for handling organization account movements. |
| <a name="output_policy_key"></a> [policy\_key](#output\_policy\_key) | The object key of the tagging policy in the policy bucket. |
| <a name="output_policy_version"></a> [policy\_version](#output\_policy\_version) | The sha256 of the tagging policy, used to force re-evaluation when the policy changes. |
<!-- END_TF_DOCS -->
