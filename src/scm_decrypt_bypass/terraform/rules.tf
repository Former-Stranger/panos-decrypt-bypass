###############################################################################
# 3. No-decrypt decryption policy rules
#
# One rule per bypass type so the rule name in the decryption/traffic log tells
# you why a session was not decrypted. A rule is only created when its list has
# entries. Order follows Palo's recommendation (IP exceptions first, broad
# categories last) and the rules are chained: the first uses rule_placement,
# each later one is placed "after" the previous enabled rule.
###############################################################################

locals {
  url_edls = concat(var.existing_url_edls, [for k, e in scm_external_dynamic_list.this : e.name if var.edls[k].type == "url"])
  ip_edls  = concat(var.existing_ip_edls, [for k, e in scm_external_dynamic_list.this : e.name if var.edls[k].type == "ip"])

  rule_match = {
    destinations = {
      description = "Destination IPs/FQDNs from bypass/no-decrypt-destinations.txt and IP EDLs"
      enabled     = length(local.bypass.destinations) + length(var.existing_ip_edls) + length([for e in values(var.edls) : e if e.type == "ip"]) > 0
      destination = concat([for a in scm_address.destination : a.name], local.ip_edls)
    }
    sources = {
      description = "Source IPs/FQDNs from bypass/no-decrypt-sources.txt"
      enabled     = length(local.bypass.sources) > 0
      source      = [for a in scm_address.source : a.name]
    }
    users = {
      description = "Users/groups from bypass/no-decrypt-users.txt"
      enabled     = length(local.bypass.users) > 0
      source_user = sort(keys(local.bypass.users))
    }
    urls = {
      description = "Hostnames from bypass/no-decrypt-urls.txt and URL EDLs"
      enabled     = length(local.bypass.urls) + length(var.existing_url_edls) + length([for e in values(var.edls) : e if e.type == "url"]) > 0
      category    = concat(scm_url_category.no_decrypt[*].name, local.url_edls)
    }
    categories = {
      description = "Predefined URL categories from bypass/no-decrypt-categories.txt"
      enabled     = length(local.bypass.categories) > 0
      category    = sort(keys(local.bypass.categories))
    }
  }

  rule_order    = ["destinations", "sources", "users", "urls", "categories"]
  enabled_rules = [for k in local.rule_order : k if local.rule_match[k].enabled]

  rule_placement = {
    for i, k in local.enabled_rules : k => i == 0 ? var.rule_placement : {
      relative_position = "after"
      target_rule       = "${var.name_prefix}-${local.enabled_rules[i - 1]}"
    }
  }

  profile = var.create_no_decrypt_profile ? scm_decryption_profile.no_decrypt[0].name : var.no_decrypt_profile

  rules = {
    for k, m in local.rule_match : k => {
      folder            = local.location.folder
      snippet           = local.location.snippet
      name              = "${var.name_prefix}-${k}"
      description       = "Managed by Terraform. ${m.description}."
      relative_position = try(local.rule_placement[k].relative_position, null)
      target_rule       = try(local.rule_placement[k].target_rule, null)
      from              = var.from_zones
      to                = var.to_zones
      source            = try(m.source, var.source_addresses)
      destination       = try(m.destination, ["any"])
      source_user       = try(m.source_user, ["any"])
      category          = try(m.category, ["any"])
      service           = var.services
      profile           = local.profile
      log_setting       = var.log_setting
      log_success       = var.log_success
      log_fail          = var.log_fail
      tag               = [scm_tag.bypass.name]
    }
  }
}

# Separate module calls (not for_each) so each rule is created only after the
# rule it is positioned "after" already exists.

module "rule_destinations" {
  source = "./modules/no-decrypt-rule"
  count  = local.rule_match.destinations.enabled ? 1 : 0
  rule   = local.rules.destinations
}

module "rule_sources" {
  source     = "./modules/no-decrypt-rule"
  count      = local.rule_match.sources.enabled ? 1 : 0
  rule       = local.rules.sources
  depends_on = [module.rule_destinations]
}

module "rule_users" {
  source     = "./modules/no-decrypt-rule"
  count      = local.rule_match.users.enabled ? 1 : 0
  rule       = local.rules.users
  depends_on = [module.rule_destinations, module.rule_sources]
}

module "rule_urls" {
  source     = "./modules/no-decrypt-rule"
  count      = local.rule_match.urls.enabled ? 1 : 0
  rule       = local.rules.urls
  depends_on = [module.rule_destinations, module.rule_sources, module.rule_users]
}

module "rule_categories" {
  source     = "./modules/no-decrypt-rule"
  count      = local.rule_match.categories.enabled ? 1 : 0
  rule       = local.rules.categories
  depends_on = [module.rule_destinations, module.rule_sources, module.rule_users, module.rule_urls]
}
