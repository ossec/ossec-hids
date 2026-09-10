variable "aws_account_id" {
  description = "AWS account in which the IAM role and OIDC provider are managed."
  type        = string
  default     = "113345163213"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "aws_region" {
  description = "AWS region containing the td-ossec-agents bucket."
  type        = string
}

variable "circleci_org_id" {
  description = "CircleCI organization UUID used by the organization-specific OIDC issuer and audience."
  type        = string

  validation {
    condition     = length(trimspace(var.circleci_org_id)) > 0
    error_message = "circleci_org_id must be provided."
  }
}

variable "role_name" {
  description = "IAM role assumed by CircleCI through OIDC."
  type        = string
  default     = "CircleCI-OSSEC-Packages-Publisher"
}

variable "artifact_bucket" {
  description = "S3 bucket that receives OSSEC package artifacts."
  type        = string
  default     = "td-ossec-agents"
}

variable "artifact_prefix" {
  description = "S3 prefix that CircleCI may write to."
  type        = string
  default     = "installer"

  validation {
    condition     = length(trim(var.artifact_prefix, "/")) > 0
    error_message = "artifact_prefix must not be empty."
  }
}

variable "tags" {
  description = "Additional tags applied to the IAM role and OIDC provider."
  type        = map(string)
  default = {
    ManagedBy = "Terraform"
    Service   = "OSSEC"
    Purpose   = "CircleCI package publishing"
  }
}
