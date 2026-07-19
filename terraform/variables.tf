variable "aws_region" {
  description = "AWS region for the decommissionable lab stack."
  type        = string
  default     = "us-east-2"
}

variable "name_prefix" {
  description = "Short prefix used for lab resources."
  type        = string
  default     = "aegis-soar-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,32}$", var.name_prefix))
    error_message = "name_prefix must be 3-32 lowercase letters, digits, or hyphens."
  }
}

variable "allowed_target_role_names" {
  description = "Existing lab IAM role names eligible for the quarantine policy."
  type        = set(string)

  validation {
    condition = length(var.allowed_target_role_names) > 0 && alltrue([
      for role in var.allowed_target_role_names : can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", role))
    ])
    error_message = "Provide at least one valid IAM role name."
  }
}

variable "alert_webhook_secret_arn" {
  description = "Secrets Manager ARN containing the HMAC secret used by the alert sender."
  type        = string
}

variable "slack_webhook_url_secret_arn" {
  description = "Secrets Manager ARN containing the Slack incoming-webhook URL."
  type        = string
}

variable "slack_signing_secret_arn" {
  description = "Secrets Manager ARN containing the Slack app signing secret."
  type        = string
}

variable "openai_api_key_secret_arn" {
  description = "Optional Secrets Manager ARN for model-assisted narrative generation."
  type        = string
  default     = null
  nullable    = true
}

variable "openai_model" {
  description = "Optional explicit model ID; omit with the API-key secret for deterministic narratives."
  type        = string
  default     = null
  nullable    = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the lab functions."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Tags applied to supported resources."
  type        = map(string)
  default = {
    Project     = "AegisSOAR"
    Environment = "lab"
    ManagedBy   = "Terraform"
  }
}
