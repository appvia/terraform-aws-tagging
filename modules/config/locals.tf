
locals {
  ## The ARN of the policy bucket, derived from the bucket name
  policy_bucket_arn = format("arn:%s:s3:::%s", data.aws_partition.current.partition, var.policy_bucket_name)
}
