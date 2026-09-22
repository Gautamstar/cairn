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
  # Slugs rather than hostnames, and deliberately. The site ID is part of the
  # DynamoDB partition key, so changing one splits its history into two
  # unconnected halves. A slug survives a move to a custom domain; a hostname
  # forces a choice between fracturing the data and keeping an ID that no
  # longer describes anything.
  #
  #   portfolio  gautamstar.github.io
  #   fitmit     fitpdf-rose.vercel.app
  #   edaproj    eda-proj.vercel.app
  type    = list(string)
  default = ["portfolio", "fitmit", "edaproj"]

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

# ---------------------------------------------------------------------------
# Billing. All empty by default, which leaves billing switched off: every
# account is on the free plan and the upgrade routes answer 503. Nothing else
# depends on these being set.
# ---------------------------------------------------------------------------

variable "stripe_webhook_secret" {
  description = <<-EOT
    Signing secret of the Stripe webhook endpoint (starts `whsec_`). Stripe
    shows it once, on the endpoint's page, after you add
    https://<distribution>/api/billing/webhook listening for
    `checkout.session.completed` and `customer.subscription.deleted`.

    Marked sensitive, but it still lands in Terraform state and the Lambda's
    configuration. It can only prove requests came from Stripe; it cannot move
    money. Move it to SSM beside the visitor salt if that trade stops being
    acceptable.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "stripe_starter_url" {
  description = "Starter Payment Link URL, e.g. https://buy.stripe.com/abc123."
  type        = string
  default     = ""
}

variable "stripe_starter_link_id" {
  description = <<-EOT
    Starter Payment Link id (starts `plink_`), from the link's page in the
    Stripe dashboard. The plan is decided by this id in the webhook, never by
    anything in the URL the customer followed, which they could edit.
  EOT
  type        = string
  default     = ""
}

variable "stripe_pro_url" {
  description = "Pro Payment Link URL."
  type        = string
  default     = ""
}

variable "stripe_pro_link_id" {
  description = "Pro Payment Link id (starts `plink_`)."
  type        = string
  default     = ""
}

variable "stripe_portal_url" {
  description = <<-EOT
    Customer Portal login link (Stripe dashboard, Settings, Billing, Customer
    portal). Paying customers get a "Manage billing" link to it for cancelling
    and updating their card. Turn plan switching off in the portal settings:
    a switch there changes the Stripe subscription without telling Cairn.
  EOT
  type        = string
  default     = ""
}
