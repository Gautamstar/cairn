variable "region" {
  description = "Home region for the Lambdas, table, and buckets. CloudFront is global and unaffected."
  type        = string
  default     = "us-east-2"
}

variable "sites" {
  description = <<-EOT
    Sites the rollup aggregates, matching the `data-site` attribute on each
    tracker tag. A static list rather than a registry table: adding a site is a
    variable change, and a lookup table would be infrastructure for a
    multi-tenant product that does not exist.
  EOT
  type        = list(string)
  default     = ["gautamstar.github.io"]

  validation {
    condition     = length(var.sites) > 0
    error_message = "At least one site is required, or the rollup has nothing to aggregate."
  }
}

variable "salt_parameter_name" {
  description = <<-EOT
    SSM parameter holding the visitor-hashing secret.

    Terraform never creates or reads this value, only grants access to it by
    name. See infra/README.md for why, and for the one command that creates it.
  EOT
  type        = string
  default     = "/cairn/visitor-salt"
}

variable "log_retention_days" {
  description = <<-EOT
    CloudWatch Logs retention. Log groups default to never expiring, which is
    the most common way a free-tier account starts costing money months later.
  EOT
  type        = number
  default     = 14
}

variable "table_capacity" {
  description = <<-EOT
    Provisioned read and write capacity units.

    Provisioned, not on-demand, and that is deliberate: the perpetual 25 RCU /
    25 WCU free tier does not apply to on-demand billing. Five of each is well
    inside it and ample for this traffic.
  EOT
  type        = number
  default     = 5
}
