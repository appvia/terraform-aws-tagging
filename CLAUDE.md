# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Terraform module for AWS tagging compliance enforcement across AWS Organizations. It uses AWS Config custom rules with Lambda functions to evaluate resource tags against a centrally-defined YAML policy stored in S3.

## Architecture

The framework consists of four main components:

1. **Root Module** - Creates the S3 bucket holding the tagging policy, resource type mappings, and optional account inventory
2. **Validation Module** (`modules/validation/`) - Lambda function that evaluates tagging compliance against the YAML policy
3. **Config Module** (`modules/config/`) - AWS Config custom rules that invoke the validation Lambda
4. **Pack Module** (`modules/pack/`) - Wraps validation into AWS Config Conformance Packs for org-wide deployment

### Key Design Patterns

- **YAML Policy Language**: Rich, configuration-driven rules with filter/assert chains, supporting organizational paths, account IDs, and account tags
- **S3-Based Storage**: Policy, mappings, and account inventory stored in a versioned, encrypted S3 bucket
- **Organization-Wide Access**: Bucket policies allow cross-account read access via `aws:PrincipalOrgID`
- **Separation of Concerns**: Validation module (Lambda) is separate from Config module (Config rules)
- **Two Deployment Patterns**: Per-account Config rules OR organization conformance packs
- **Automatic Re-evaluation**: Policy and inventory changes trigger Config re-evaluation via version hash parameters

## Development Commands

### Initialization
```bash
make init                    # Initialize all Terraform directories
terraform init -backend=false  # Init without backend (for local dev)
```

### Testing
```bash
make tests                   # Run Terraform native tests (*.tftest.hcl)
make python-tests            # Run Python unit tests for Lambda handler
pytest modules/validation/assets/handler_test.py -v  # Run specific Python tests
```

### Validation & Linting
```bash
make validate                # Validate all Terraform (root, modules, examples)
make lint                    # Run tflint on all Terraform code
make security                # Run trivy security scans
make format                  # Format Terraform and Python code
```

### Individual Targets
```bash
make validate-modules        # Validate only modules/
make validate-examples       # Validate only examples/
make lint-modules            # Lint only modules/
make security-modules        # Security scan only modules/
```

### Documentation
```bash
make documentation           # Generate all README.md files with terraform-docs
make documentation-modules   # Generate docs for modules only
make documentation-examples  # Generate docs for examples only
```

### Complete Workflow
```bash
make all                     # Run full workflow: init, validate, tests, lint, security, format, documentation
```

## Code Structure

### Root Module Files
- `storage.tf` - S3 bucket, bucket policy, and S3 objects (policy, mappings, inventory)
- `organizations.tf` - Organizations Lambda for account inventory management
- `variables.tf` - Input variables for bucket configuration, policy, mappings, and organizations
- `outputs.tf` - Exports bucket ARN/name, object keys, version hashes, and KMS key ARN
- `data.tf` - Data sources for account ID and organization
- `locals.tf` - Local values for organization ID resolution and merged mappings

### Module Structure
Each module follows the same pattern:
- `main.tf` - Primary resource definitions
- `variables.tf` - Module inputs
- `outputs.tf` - Module outputs
- `data.tf` - Data sources (if needed)
- `locals.tf` - Local computed values
- `README.md` - Auto-generated documentation
- `terraform.tf` - Terraform version constraints
- `provider.tf` - Terraform provider confuiguration

### Lambda Handler (Python)
- **Validation Lambda**: `modules/validation/assets/handler.py`
  - Runtime: Python 3.12
  - Entry point: `lambda_handler(event, context)`
  - Dependencies: `policy.py` (parser), `engine.py` (evaluator), `store.py` (S3 caching)
  - Tests: `modules/validation/assets/handler_test.py`, `policy_test.py`, `engine_test.py`, `store_test.py`
- **Organizations Lambda**: `modules/organizations/assets/handler.py`
  - Syncs account inventory with tags to S3 as `accounts.yaml`
  - Triggers on Organizations events (create, close, move, tag changes) and daily schedule
  - Re-puts conformance pack with new InventoryVersion when accounts change
  - Tests: `modules/organizations/assets/handler_test.py`

### Testing
- Native Terraform tests in `tests/*.tftest.hcl`
- Uses mock provider pattern for unit tests
- Python tests use pytest framework

## Working with Lambda Functions

### Validation Lambda
The validation Lambda evaluates AWS Config events against the YAML policy:

1. Loads and caches policy, mappings, and inventory from S3 (with TTL and ETag revalidation)
2. Parses the YAML policy (`policy.py`) and validates resource tags against rules (`engine.py`)
3. Filters rules by resource type (via mappings), organizational path, account ID, and account tags
4. Returns compliance status: COMPLIANT (no errors), NON_COMPLIANT (error violations), or NOT_APPLICABLE (no rules matched)

### Key Validation Logic
- **Policy Grammar**: Chains of `filter` (narrows scope) and `assert` (reports violations) steps
- **Targets**: `tag`, `type` (Terraform or AWS:: names), `address` (plan-time only), `organizational_path`, `account_id`, `account_tag`
- **Operators**: `present`, `equals`, `in`, `contains`, `starts_with`, `ends_with`, `matches` (regex), case operators, `not`
- **Severity**: `error` (NON_COMPLIANT) or `warning` (logged, COMPLIANT)
- **Taggable Types**: Only resource types in `mappings.yaml` are evaluated; unmapped types return NOT_APPLICABLE
- **Missing Inventory**: Rules using `organizational_path` or `account_tag` are ignored when no inventory is configured or the account is missing

### Organizations Lambda
Maintains the account inventory in `accounts.yaml`:

1. Lists all accounts via Organizations API and retrieves tags for each
2. Writes `accounts.yaml` (AccountId, AccountName, OUPath, Status, Tags, LastUpdated) only when changed
3. Reconciles the conformance pack's InventoryVersion parameter to trigger org-wide re-evaluation
4. Triggers: EventBridge (CreateAccount, CloseAccount, MoveAccount, TagResource, UntagResource in us-east-1) + daily schedule

## Module Dependencies

- **config** and **pack** modules depend on the root module's S3 bucket outputs
- **config** and **pack** modules create validation Lambdas (or accept an external Lambda ARN)
- Root module's **organizations** block creates the inventory Lambda (optional)
- All modules require AWS provider >= 6.0.0

## Important Notes

### Policy Validation
The policy can be validated at two levels:
1. **Terraform Plan-Time**: The root module's `policy` variable validates basic YAML shape (`version: 1`, `rules` is a list)
2. **Full Validation**: Run `python3 modules/validation/assets/policy.py <file>` in CI to validate the full grammar before apply

### S3 Bucket
- **Versioning**: Enabled to track policy/mappings/inventory history
- **Encryption**: AES256 (default) or `aws:kms` when a `kms_key_arn` is provided
- **Access**: Public access blocked; bucket policy grants `s3:GetObject` to `aws:PrincipalOrgID` and management account
- **TLS-Only**: Bucket policy denies requests without `aws:SecureTransport`

### KMS Key Policy (when using customer-managed keys)
The consumer-supplied KMS key must grant:
- `kms:Decrypt` to the organization principal (for validation Lambdas in member accounts)
- `kms:GenerateDataKey` and `kms:Decrypt` to the organizations Lambda (for writing inventory)

### Cross-Account Access
The framework supports cross-account Lambda invocation via:
- Organization condition in S3 bucket policy (`aws:PrincipalOrgID`)
- Lambda permissions with organization principal (Config rules in member accounts invoke Lambda in management account)

### Two Deployment Patterns
1. **Per-Account Config Rules**: Deploy config module in each account separately (known limitation: inventory changes do not trigger re-evaluation without ScheduledNotification handling)
2. **Organization Conformance Pack**: Deploy pack module once in management account (recommended; inventory changes trigger org-wide re-evaluation)

## Testing Strategy

When making changes:
1. Run `make validate` to check Terraform syntax
2. Run `make tests` to execute Terraform tests
3. For Lambda changes, run `make python-tests`
4. Run `make lint` and `make security` before committing
5. Use `make format` to ensure consistent formatting

## Common Development Tasks

### Adding a New Module Variable
1. Add to `variables.tf` with proper type, description, and default
2. Update module README inputs table (auto-generated via `make documentation`)
3. Add validation block if constraints needed

### Modifying Lambda Handler
1. Edit `modules/validation/assets/handler.py`
2. Update `modules/validation/assets/handler_test.py` with new tests
3. Run `make python-tests` to verify
4. Requires Python with pytest and black installed

### Adding a New Test
1. Create or modify `tests/*.tftest.hcl`
2. Use `mock_provider "aws"` pattern for unit tests
3. Follow existing test structure: variables block, assert blocks
4. Run `make tests` to execute

### Updating Documentation
- Documentation is auto-generated from terraform-docs
- Edit `.terraform-docs.yml` for configuration
- Run `make documentation` to regenerate all READMEs
- Terraform-docs reads from variables/outputs and inserts between special markers

## Dependencies & Tools Required

- Terraform >= 1.3.0
- terraform-docs (for documentation generation)
- tflint (for Terraform linting)
- trivy (for security scanning)
- Python 3.x with pytest and black (for Lambda testing/formatting)
- Lambda packaging (`pip_requirements = true`): the host running `terraform plan`/`apply` needs a
  Python matching each Lambda runtime on `PATH` (validation `python3.14`, organizations
  `python3.12` by default) with `pip` and PyPI access; override `lambda_runtime` (config/validation)
  or `organizations.lambda.runtime` (root) to build with another interpreter
- AWS CLI (for manual testing)
- commitlint (for commit message validation)