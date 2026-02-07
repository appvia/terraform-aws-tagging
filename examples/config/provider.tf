provider "aws" {
  default_tags {
    tags = {
      "Environment" = "Testing"
      "Owner"       = "Support"
      "Product"     = "Test"
      "GitRepo"     = "https://github.com/appvia/terraform-aws-tagging"
    }
  }
}