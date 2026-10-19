## The partition, used to build ARNs in the lambda policy
data "aws_partition" "current" {}

## The current account, used to scope the conformance pack permissions
data "aws_caller_identity" "current" {}
