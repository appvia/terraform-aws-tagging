output "accounts_key" {
  description = "The object key of the account inventory in the policy bucket, or null when organizations is not enabled."
  value       = local.accounts_key
}

output "bucket_arn" {
  description = "The ARN of the S3 bucket holding the tagging policy, mappings and inventory."
  value       = aws_s3_bucket.policy.arn
}

output "bucket_name" {
  description = "The name of the S3 bucket holding the tagging policy, mappings and inventory."
  value       = aws_s3_bucket.policy.id
}

output "kms_key_arn" {
  description = "The ARN of the KMS key encrypting the policy bucket, or null when AES256 is used."
  value       = var.bucket.kms_key_arn
}

output "mappings_key" {
  description = "The object key of the resource type mappings in the policy bucket."
  value       = aws_s3_object.mappings.key
}

output "mappings_version" {
  description = "The sha256 of the rendered mappings, used to force re-evaluation when the mappings change."
  value       = sha256(local.mappings)
}

output "organizations_id" {
  description = "The ID of the AWS Organization allowed to read the policy bucket."
  value       = local.organizations_id
}

output "organizations_lambda_arn" {
  description = "The ARN of the Lambda function used for handling organization account movements."
  value       = try(module.organizations_handler[0].lambda_arn, null)
}

output "organizations_lambda_name" {
  description = "The name of the Lambda function used for handling organization account movements."
  value       = try(module.organizations_handler[0].lambda_name, null)
}

output "policy_key" {
  description = "The object key of the tagging policy in the policy bucket."
  value       = aws_s3_object.policy.key
}

output "policy_version" {
  description = "The sha256 of the tagging policy, used to force re-evaluation when the policy changes."
  value       = sha256(var.policy)
}
