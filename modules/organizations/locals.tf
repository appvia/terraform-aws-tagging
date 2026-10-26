locals {
  ## The event bridge event pattern for organization account creation, closure, moves and
  ## tag changes. Organizations is a global service; its CloudTrail events are delivered
  ## to EventBridge in us-east-1 only, so this rule only fires when deployed there.
  accounts_event_pattern = jsonencode({
    "source" : ["aws.organizations"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["organizations.amazonaws.com"],
      "eventName" : ["CreateAccount", "CloseAccount", "MoveAccount", "TagResource", "UntagResource"]
    }
  })

  ## The S3 object ARN of the conformance pack template (s3://bucket/key)
  conformance_pack_template_arn = var.conformance_pack_template_uri == null ? null : format("arn:%s:s3:::%s", data.aws_partition.current.partition, trimprefix(var.conformance_pack_template_uri, "s3://"))

  ## Environment variables enabling the conformance pack re-evaluation, only when configured
  conformance_pack_environment = var.conformance_pack_name == null ? {} : merge(
    { CONFORMANCE_PACK_NAME = var.conformance_pack_name },
    var.conformance_pack_template_uri == null ? {} : { CONFORMANCE_PACK_TEMPLATE_URI = var.conformance_pack_template_uri },
  )
}
