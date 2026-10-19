variable "bucket" {
  description = "Configuration for the S3 bucket holding the tagging policy, the resource type mappings and the account inventory."
  type = object({
    ## The name of the S3 bucket to provision.
    name = optional(string, "tagging-compliance")
    ## The ARN of an existing KMS key used to encrypt the bucket (aws:kms). When null, AES256 is used. The module never creates a key.
    kms_key_arn = optional(string)
    ## Whether to delete all objects (including versions) when the bucket is destroyed.
    force_destroy = optional(bool, false)
  })
  default = {}
}

variable "enable_organizations" {
  description = "Enable organization access to the policy bucket. When enabled, allows any account in the organization to read the policy, mappings and inventory."
  type        = bool
  default     = true
}

variable "mappings" {
  description = "Additional Terraform to AWS Config resource type mappings (e.g. aws_s3_bucket = \"AWS::S3::Bucket\"), merged over the shipped mappings file. The mappings also define the taggable resource types."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for v in values(var.mappings) : startswith(v, "AWS::")])
    error_message = "Every mapping value must be an AWS Config resource type starting with AWS:: (e.g. AWS::S3::Bucket)."
  }
}

variable "organizations" {
  description = "Configuration for the organizations inventory lambda. When null, no account inventory is maintained."
  type = object({
    ## The name of the conformance pack to re-put when the inventory changes (wired by the organizations handler).
    conformance_pack_name = optional(string)
    lambda = optional(object({
      ## The description of the Lambda function to handle AWS Organization account movements.
      description = optional(string, "Handles AWS Organization account movements for tagging compliance.")
      ## The log level for the Lambda function. Valid values are DEBUG, INFO, WARNING, ERROR, CRITICAL.
      log_level = optional(string, "INFO")
      ## The amount of memory in MB allocated to the Lambda function.
      memory_size = optional(number, 128)
      ## The name of the Lambda function to handle AWS Organization account movements.
      name = optional(string, "organization-compliance")
      ## The runtime environment for the Lambda function.
      runtime = optional(string, "python3.12")
      ## The timeout for the Lambda function in seconds.
      timeout = optional(number, 30)
    }), {})
  })
  default = null
}

variable "organizations_id" {
  description = "AWS Organization ID allowed to read the policy bucket."
  type        = string
  default     = null
}

variable "policy" {
  description = "The tagging policy as YAML content (version: 1), uploaded to the bucket as policy.yaml. Typically file(\"tagging-policy.yaml\")."
  type        = string

  validation {
    condition     = can(yamldecode(var.policy))
    error_message = "The policy must be valid YAML."
  }

  validation {
    condition     = try(yamldecode(var.policy).version == 1, false)
    error_message = "The policy must declare version: 1."
  }

  validation {
    condition     = can(tolist(yamldecode(var.policy).rules))
    error_message = "The policy must contain a rules list."
  }
}

variable "tags" {
  description = "A map of tags to apply to all resources."
  type        = map(string)
  default     = {}
}
