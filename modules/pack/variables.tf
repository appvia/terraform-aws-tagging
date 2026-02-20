variable "compliance_rule_table_arn" {
  description = "ARN of the DynamoDB table containing compliance rules"
  type        = string
}

variable "conformance_pack_name" {
  description = "Name of the AWS Config Conformance Pack"
  type        = string
  default     = "tagging-compliance"
}

variable "config_frequency" {
  description = "Maximum frequency for Config rule evaluation"
  type        = string
  default     = "TWENTY_FOUR_HOURS"
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.config_frequency)
    error_message = "config_frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours"
  }
}

variable "config_rule_name" {
  description = "Name of the AWS Config rule within the conformance pack"
  type        = string
  default     = "tagging-compliance"
}

variable "cloudwatch_logs_kms_key_id" {
  description = "KMS key ID for encrypting CloudWatch Logs (optional)"
  type        = string
  default     = null
}

variable "cloudwatch_logs_log_group_class" {
  description = "Log group class for CloudWatch Logs. Valid values are STANDARD and INFREQUENT_ACCESS."
  type        = string
  default     = "STANDARD"
}

variable "cloudwatch_logs_retention_in_days" {
  description = "Number of days to retain CloudWatch Logs. Valid values are 0 (retain indefinitely), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, or 1827."
  type        = number
  default     = 7
}

variable "deploy_organization_wide" {
  description = "Whether to deploy the conformance pack organization-wide (requires Organizations management account)"
  type        = bool
  default     = false
}

variable "excluded_accounts" {
  description = "List of AWS account IDs to exclude from organization conformance pack deployment"
  type        = list(string)
  default     = []
}

variable "input_parameters" {
  description = "Map of input parameters to pass to the conformance pack"
  type        = map(string)
  default     = {}
}

variable "lambda_function_arn" {
  description = "ARN of the Lambda function that evaluates compliance"
  type        = string
  default     = null
}

variable "pack_description" {
  description = "Description of the conformance pack"
  type        = string
  default     = "AWS Config Conformance Pack for validating resource tagging compliance"
}

variable "resource_types" {
  description = "List of AWS resource types to evaluate (e.g., AWS::EC2::Instance)"
  type        = list(string)
  default = [
    "AWS::ACM::Certificate",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::CloudFormation::Stack",
    "AWS::DynamoDB::Table",
    "AWS::EC2::Instance",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Subnet",
    "AWS::EC2::VPC",
    "AWS::EC2::VPNConnection",
    "AWS::EC2::Volume",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBSnapshot",
    "AWS::Redshift::Cluster",
    "AWS::S3::Bucket",
  ]
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket to store the conformance pack template"
  type        = string
}

variable "s3_enable_versioning" {
  description = "Enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "s3_kms_key_id" {
  description = "KMS key ID for S3 bucket encryption (optional)"
  type        = string
  default     = null
}

variable "s3_template_key" {
  description = "S3 object key for the conformance pack template"
  type        = string
  default     = "conformance-packs/tagging-compliance.yaml"
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
