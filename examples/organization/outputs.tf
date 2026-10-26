output "bucket_name" {
  description = "The name of the S3 bucket holding the tagging policy"
  value       = module.tagging.bucket_name
}

output "bucket_arn" {
  description = "The ARN of the S3 bucket holding the tagging policy"
  value       = module.tagging.bucket_arn
}

output "policy_key" {
  description = "The S3 object key of the tagging policy"
  value       = module.tagging.policy_key
}

output "conformance_pack_name" {
  description = "The name of the organization conformance pack"
  value       = module.pack.conformance_pack_name
}
