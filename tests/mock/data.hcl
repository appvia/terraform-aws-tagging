mock_data "aws_dynamodb_table" {
  defaults = {
    hash_key = "ResourceType"
    range_key = "RuleId"
    table_name = "tagging-compliance"
  }
}

mock_data "aws_region" {
  defaults = {
    region = "eu-west-2"
    name = "eu-west-2"
  }
}

mock_data "aws_partition" {
  defaults = {
    partition = "aws"
    dns_suffix = "amazonaws.com"
  }
}

mock_data "aws_caller_identity" {
  defaults = {
    account_id = "123456789012"
    arn = "arn:aws:iam::123456789012:user/test"
    user_id = "AIDAEXAMPLE"
  }
}

mock_data "aws_iam_policy_document" {
  defaults = {
    json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
  }
}

mock_data "aws_iam_policy" {
  defaults = {
    arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
    name = "AWSXRayDaemonWriteAccess"
    path = "/"
    policy_id = "ANPAI23HZ27SI6FQMGNQ2"
    description = "AWS X-Ray daemon write access"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords"
          ]
          Resource = "*"
        }
      ]
    })
  }
}

mock_data "aws_availability_zones" {
  defaults = {
    names = [
      "eu-west-2a",
      "eu-west-2b",
      "eu-west-2c"
    ]
  }
}