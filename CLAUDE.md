# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Terraform module for AWS tagging compliance enforcement across AWS Organizations. It uses AWS Config custom rules with Lambda functions to evaluate resource tags against centrally-defined rules stored in DynamoDB.

## Architecture

The framework consists of five main components:

1. **Root Module** - Creates the central DynamoDB table with organization-wide access policies
2. **Validation Module** (`modules/validation/`) - Lambda function that evaluates tagging compliance
3. **Config Module** (`modules/config/`) - AWS Config custom rules that invoke the Lambda
4. **Compliance Module** (`modules/compliance/`) - Manages compliance rules in DynamoDB
5. **Pack Module** (`modules/pack/`) - Wraps everything into AWS Config Conformance Packs for org-wide deployment

### Key Design Patterns

- **Central Rule Repository**: DynamoDB table in management account stores all tagging rules
- **Organization-Wide Access**: Resource policies allow cross-account read access
- **Separation of Concerns**: Validation module (Lambda) is separate from Config module (Config rules)
- **Two Deployment Patterns**: Per-account Config rules OR organization conformance packs

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
- `main.tf` - DynamoDB table, resource policy, and compliance rules integration
- `variables.tf` - Input variables for table configuration and rules
- `outputs.tf` - Exports table ARN and name
- `data.tf` - Data sources for account ID and organization
- `locals.tf` - Local values for organization ID resolution

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
- Location: `modules/validation/assets/handler.py`
- Runtime: Python 3.12
- Entry point: `lambda_handler(event, context)`
- Key classes: `Resource`, `Rule`, `Evaluation` `Evaluations`
- Tests: `modules/validation/assets/handler_test.py`

### Testing
- Native Terraform tests in `tests/*.tftest.hcl`
- Uses mock provider pattern for unit tests
- Python tests use pytest framework

## Working with Lambda Functions

The Lambda handler evaluates AWS Config events:

1. Extracts resource details from AWS Config event
2. Queries DynamoDB for applicable rules (by ResourceType and AccountId)
3. Evaluates tags against rules (required/optional, values, regex patterns)
4. Returns compliance status: COMPLIANT, NON_COMPLIANT, or NOT_APPLICABLE

### Key Lambda Logic
- Rules are filtered by: resource type pattern match, account ID match, enabled status
- Tag validation supports: specific values list OR regex pattern (ValuePattern)
- Optional tags (Required=false) are only validated if present

## Module Dependencies

- **config** module depends on **validation** module (internally invoked)
- **compliance** module writes to DynamoDB table created by root module
- **pack** module requires **validation** module's Lambda ARN
- All modules require AWS provider >= 6.0.0

## Important Notes

### DynamoDB Schema
- Hash Key: `ResourceType` (string)
- Range Key: `RuleId` (string)
- Required attributes: ResourceType, RuleId, Tag, Enabled, Required
- Optional attributes: Values (list), ValuePattern (string), AccountIds (list)

### Cross-Account Access
The framework supports cross-account Lambda invocation via:
- Organization condition in DynamoDB resource policy (`aws:PrincipalOrgID`)
- Lambda permissions with organization principal
- Config rules in member accounts invoke Lambda in management account

### Two Deployment Patterns
1. **Per-Account Config Rules**: Deploy config module in each account separately
2. **Organization Conformance Pack**: Deploy pack module once in management account (recommended)

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
- AWS CLI (for manual testing)
- commitlint (for commit message validation)