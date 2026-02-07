locals {
  ## The current account id 
  account_id = data.aws_caller_identity.current.account_id
}