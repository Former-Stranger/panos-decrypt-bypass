# A single "no-decrypt" decryption policy rule in the pre-rulebase. Wrapped in
# a module only so the root can order rule creation with depends_on.

terraform {
  required_providers {
    scm = {
      source = "PaloAltoNetworks/scm"
    }
  }
}

variable "rule" {
  type = object({
    folder            = optional(string)
    snippet           = optional(string)
    name              = string
    description       = string
    relative_position = optional(string)
    target_rule       = optional(string)
    from              = list(string)
    to                = list(string)
    source            = list(string)
    destination       = list(string)
    source_user       = list(string)
    category          = list(string)
    service           = list(string)
    profile           = optional(string)
    log_setting       = optional(string)
    log_success       = bool
    log_fail          = bool
    tag               = list(string)
  })
}

resource "scm_decryption_rule" "this" {
  folder  = var.rule.folder
  snippet = var.rule.snippet

  name              = var.rule.name
  description       = var.rule.description
  action            = "no-decrypt"
  position          = "pre"
  relative_position = var.rule.relative_position
  target_rule       = var.rule.target_rule

  from        = var.rule.from
  to          = var.rule.to
  source      = var.rule.source
  destination = var.rule.destination
  source_user = var.rule.source_user
  category    = var.rule.category
  service     = var.rule.service

  type = {
    ssl_forward_proxy = {}
  }

  profile     = var.rule.profile
  log_setting = var.rule.log_setting
  log_success = var.rule.log_success
  log_fail    = var.rule.log_fail
  tag         = var.rule.tag
}

output "name" {
  value = scm_decryption_rule.this.name
}
