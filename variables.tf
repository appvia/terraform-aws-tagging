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
    ## The name of the organization conformance pack to re-put with a new InventoryVersion when the
    ## inventory changes (forces an org-wide re-evaluation). Requires conformance_pack_template_uri.
    conformance_pack_name = optional(string)
    ## The S3 URI (s3://bucket/key) of the conformance pack template. Build it from the values passed
    ## to the pack module's s3_bucket_name and s3_template_key; referencing the pack module output
    ## s3_template_uri creates a dependency cycle, as the pack consumes this module's accounts_key.
    conformance_pack_template_uri = optional(string)
    ## Trigger the sync on account create, close, move, tag and untag events. Organizations CloudTrail
    ## events are delivered to EventBridge only in us-east-1, so the module must be deployed in
    ## us-east-1 for this trigger to fire; elsewhere only the scheduled sync runs.
    enable_account_event_sync = optional(bool, true)
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
      timeout = optional(number, 60)
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
    ## A YAML sequence decodes to a tuple; accept heterogeneous rules and [], reject maps and scalars
    condition     = try(length(yamldecode(var.policy).rules), -1) >= 0 && !can(keys(yamldecode(var.policy).rules)) && !can(tostring(yamldecode(var.policy).rules))
    error_message = "The policy must contain a rules list."
  }
}

variable "tags" {
  description = "A map of tags to apply to all resources."
  type        = map(string)
  default     = {}
}
