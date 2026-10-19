## Provision the S3 bucket holding the tagging policy, mappings and account inventory
resource "aws_s3_bucket" "policy" {
  bucket        = var.bucket.name
  force_destroy = var.bucket.force_destroy
  tags          = var.tags
}

## Enable versioning so previous policies can be recovered
resource "aws_s3_bucket_versioning" "policy" {
  bucket = aws_s3_bucket.policy.id

  versioning_configuration {
    status = "Enabled"
  }
}

## Block all public access to the policy bucket
resource "aws_s3_bucket_public_access_block" "policy" {
  bucket = aws_s3_bucket.policy.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

## Encrypt the policy bucket, using the consumer supplied KMS key when provided
resource "aws_s3_bucket_server_side_encryption_configuration" "policy" {
  bucket = aws_s3_bucket.policy.id

  rule {
    bucket_key_enabled = var.bucket.kms_key_arn != null

    apply_server_side_encryption_by_default {
      sse_algorithm     = var.bucket.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.bucket.kms_key_arn
    }
  }
}

## Craft the bucket policy permitting the organization and management account to read the objects;
## s3:ListBucket lets readers see NoSuchKey (e.g. no inventory yet) rather than AccessDenied
data "aws_iam_policy_document" "bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.policy.arn,
      "${aws_s3_bucket.policy.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  ## Only granted with the organization condition; without it the statement would make the bucket public
  dynamic "statement" {
    for_each = var.enable_organizations ? [1] : []

    content {
      sid    = "AllowOrganizationReadAccess"
      effect = "Allow"
      actions = [
        "s3:GetObject",
        "s3:ListBucket",
      ]
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
      resources = [
        aws_s3_bucket.policy.arn,
        "${aws_s3_bucket.policy.arn}/*",
      ]

      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [local.organizations_id]
      }
    }
  }

  statement {
    sid    = "AllowAccountReadAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    resources = [
      aws_s3_bucket.policy.arn,
      "${aws_s3_bucket.policy.arn}/*",
    ]
  }
}

## Attach the bucket policy to the policy bucket
resource "aws_s3_bucket_policy" "policy" {
  bucket = aws_s3_bucket.policy.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [
    aws_s3_bucket_public_access_block.policy,
  ]
}

## Upload the tagging policy
resource "aws_s3_object" "policy" {
  bucket       = aws_s3_bucket.policy.id
  content      = var.policy
  content_type = "application/x-yaml"
  key          = local.policy_key
  tags         = var.tags

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.policy,
    aws_s3_bucket_versioning.policy,
  ]
}

## Upload the resource type mappings (shipped defaults merged with any overrides)
resource "aws_s3_object" "mappings" {
  bucket       = aws_s3_bucket.policy.id
  content      = local.mappings
  content_type = "application/x-yaml"
  key          = local.mappings_key
  tags         = var.tags

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.policy,
    aws_s3_bucket_versioning.policy,
  ]
}
