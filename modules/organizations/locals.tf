locals {
  ## The event bridge event pattern for organization account movements
  accounts_event_pattern = jsonencode({
    "source" : ["aws.organizations"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["organizations.amazonaws.com"],
      "eventName" : ["CreateAccount", "CloseAccount"]
    }
  })
}