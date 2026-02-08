output "config_rule_arn" {
  description = "The ARN of the AWS Config rule created for tagging compliance."
  value       = module.config.config_arn
}