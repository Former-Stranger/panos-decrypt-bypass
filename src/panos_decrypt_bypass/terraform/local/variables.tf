variable "vsys" {
  description = "Virtual system to create the bypass config in. Single-vsys firewalls use vsys1."
  type        = string
  default     = "vsys1"
}

variable "name_prefix" {
  description = "Prefix for every object this config creates (rules, URL category, addresses, tag, profile)."
  type        = string
  default     = "tf-ssl-bypass"
}

variable "bypass_dir" {
  description = "Directory holding the bypass list text files."
  type        = string
  default     = "bypass"
}

# --- No-decrypt rule settings -------------------------------------------------

variable "from_zones" {
  description = "Source zones for the no-decrypt rules."
  type        = list(string)
  default     = ["any"]
}

variable "to_zones" {
  description = "Destination zones for the no-decrypt rules."
  type        = list(string)
  default     = ["any"]
}

variable "source_addresses" {
  description = "Source addresses for the no-decrypt rules: names of existing address objects/groups, or \"any\". Not used by the sources rule, which matches bypass/no-decrypt-sources.txt instead."
  type        = list(string)
  default     = ["any"]
}

variable "services" {
  description = "Services for the no-decrypt rules. \"any\" also catches TLS on non-443 ports."
  type        = list(string)
  default     = ["any"]
}

variable "rule_placement" {
  description = "Where the no-decrypt rules go in the decryption rulebase, as one block in order. relative_position is top, bottom, before or after; target_rule is required for before/after."
  type = object({
    relative_position = string
    target_rule       = optional(string)
  })
  default = { relative_position = "top" }

  validation {
    condition     = contains(["top", "bottom", "before", "after"], var.rule_placement.relative_position)
    error_message = "relative_position must be top, bottom, before or after."
  }
  validation {
    condition     = !contains(["before", "after"], var.rule_placement.relative_position) || var.rule_placement.target_rule != null
    error_message = "target_rule is required when relative_position is before or after."
  }
}

variable "log_success" {
  description = "Log sessions that match the no-decrypt rules. Undecrypted traffic is only logged when a decryption rule matches it, so leave this on for visibility."
  type        = bool
  default     = true
}

variable "log_fail" {
  description = "Log decryption failures on the no-decrypt rules."
  type        = bool
  default     = true
}

variable "log_setting" {
  description = "Optional log forwarding profile for the no-decrypt rules."
  type        = string
  default     = null
}

variable "no_decrypt_profile" {
  description = "Name of an existing decryption profile to attach to the no-decrypt rules. Ignored when create_no_decrypt_profile is true."
  type        = string
  default     = null
}

variable "create_no_decrypt_profile" {
  description = "Create and attach a no-decryption profile that blocks expired certs and untrusted issuers on bypassed traffic. Off by default: it can block the very sites you bypass (e.g. ones signed by a private CA)."
  type        = bool
  default     = false
}

# --- External dynamic lists ---------------------------------------------------

variable "existing_url_edls" {
  description = "Names of existing URL-type EDLs to add to the URL no-decrypt rule."
  type        = list(string)
  default     = []
}

variable "existing_ip_edls" {
  description = "Names of existing IP-type EDLs to add to the destination no-decrypt rule."
  type        = list(string)
  default     = []
}

variable "edls" {
  description = "EDLs to create. url-type EDLs join the URL rule; ip-type EDLs join the destination rule."
  type = map(object({
    type        = string
    source_url  = string
    recurring   = optional(string, "hourly")
    description = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for e in values(var.edls) : contains(["url", "ip"], e.type)])
    error_message = "EDL type must be \"url\" or \"ip\"."
  }
  validation {
    condition     = alltrue([for e in values(var.edls) : contains(["five_minute", "hourly"], e.recurring)])
    error_message = "EDL recurring must be \"five_minute\" or \"hourly\"."
  }
}
