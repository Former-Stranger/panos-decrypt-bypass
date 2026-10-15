###############################################################################
# No-decrypt decryption policy rules
#
# One rule per bypass type so the rule name in the decryption/traffic log tells
# you why a session was not decrypted. A rule is only created when its list has
# entries. Order follows Palo's recommendation (IP exceptions first, broad
# categories last). All of them are managed as one block, kept together at
# rule_placement.
###############################################################################

locals {
  url_edls = concat(var.existing_url_edls, [for k, e in panos_external_dynamic_list.this : e.name if var.edls[k].type == "url"])
  ip_edls  = concat(var.existing_ip_edls, [for k, e in panos_external_dynamic_list.this : e.name if var.edls[k].type == "ip"])

  rule_match = {
    destinations = {
      description = "Destination IPs/FQDNs from bypass/no-decrypt-destinations.txt and IP EDLs"
      enabled     = length(local.bypass.destinations) + length(var.existing_ip_edls) + length([for e in values(var.edls) : e if e.type == "ip"]) > 0
      destination = concat([for a in panos_address.destination : a.name], local.ip_edls)
    }
    sources = {
      description = "Source IPs/FQDNs from bypass/no-decrypt-sources.txt"
      enabled     = length(local.bypass.sources) > 0
      source      = [for a in panos_address.source : a.name]
    }
    users = {
      description = "Users/groups from bypass/no-decrypt-users.txt"
      enabled     = length(local.bypass.users) > 0
      source_user = sort(keys(local.bypass.users))
    }
    urls = {
      description = "Hostnames from bypass/no-decrypt-urls.txt and URL EDLs"
      enabled     = length(local.bypass.urls) + length(var.existing_url_edls) + length([for e in values(var.edls) : e if e.type == "url"]) > 0
      category    = concat(panos_custom_url_category.no_decrypt[*].name, local.url_edls)
    }
    categories = {
      description = "Predefined URL categories from bypass/no-decrypt-categories.txt"
      enabled     = length(local.bypass.categories) > 0
      category    = sort(keys(local.bypass.categories))
    }
  }

  rule_order    = ["destinations", "sources", "users", "urls", "categories"]
  enabled_rules = [for k in local.rule_order : k if local.rule_match[k].enabled]

  profile = var.create_no_decrypt_profile ? panos_decryption_profile.no_decrypt[0].name : var.no_decrypt_profile

  rules = {
    for k, m in local.rule_match : k => {
      name                  = "${var.name_prefix}-${k}"
      description           = "Managed by Terraform. ${m.description}."
      action                = "no-decrypt"
      type                  = { ssl_forward_proxy = {} }
      source_zones          = var.from_zones
      destination_zones     = var.to_zones
      source_addresses      = try(m.source, var.source_addresses)
      destination_addresses = try(m.destination, ["any"])
      source_user           = try(m.source_user, ["any"])
      category              = try(m.category, ["any"])
      services              = var.services
      profile               = local.profile
      log_setting           = var.log_setting
      log_success           = var.log_success
      log_fail              = var.log_fail
      tag                   = [panos_administrative_tag.bypass.name]
    }
  }

  position = {
    where = {
      top    = "first"
      bottom = "last"
      before = "before"
      after  = "after"
    }[var.rule_placement.relative_position]
    pivot    = var.rule_placement.target_rule
    directly = var.rule_placement.target_rule == null ? null : true
  }
}

resource "panos_decryption_policy_rules" "no_decrypt" {
  count = length(local.enabled_rules) > 0 ? 1 : 0

  location = local.location
  position = local.position
  rules    = [for k in local.enabled_rules : local.rules[k]]
}
