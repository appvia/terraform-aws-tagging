#####################################################################################
# Terraform module examples are meant to show an _example_ on how to use a module
# per use-case. The code below should not be copied directly but referenced in order
# to build your own root module that invokes this module
#####################################################################################

## Provision the S3 bucket with the tagging policy
module "tagging" {
  source = "../../"

  ## The tagging policy as YAML content
  policy = file("${path.module}/tagging-policy.yaml")

  ## S3 bucket configuration
  bucket = {
    name          = "tagging-compliance"
    force_destroy = true
  }
}
