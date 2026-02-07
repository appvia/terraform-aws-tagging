output "conformance_pack_arn" {
  description = "ARN of the conformance pack"
  value       = var.deploy_organization_wide ? try(aws_config_organization_conformance_pack.tagging[0].arn, null) : try(aws_config_conformance_pack.tagging[0].arn, null)
}

output "conformance_pack_id" {
  description = "ID of the conformance pack"
  value       = var.deploy_organization_wide ? try(aws_config_organization_conformance_pack.tagging[0].id, null) : try(aws_config_conformance_pack.tagging[0].id, null)
}

output "conformance_pack_name" {
  description = "Name of the conformance pack"
  value       = var.conformance_pack_name
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket storing the conformance pack template"
  value       = aws_s3_bucket.conformance_pack.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket storing the conformance pack template"
  value       = aws_s3_bucket.conformance_pack.id
}

output "s3_template_uri" {
  description = "S3 URI of the conformance pack template"
  value       = "s3://${aws_s3_bucket.conformance_pack.id}/${aws_s3_object.conformance_pack_template.key}"
}
