locals {
  location = {
    folder  = var.folder
    snippet = var.snippet
  }
}

check "exclusion_entries_are_hostnames" {
  assert {
    condition     = alltrue([for h in keys(local.bypass.exclusions) : can(regex("^(\\*\\.)*[a-z0-9_-]+(\\.[a-z0-9_*-]+)*$", h))])
    error_message = "exclusion-hostnames.txt should contain hostnames only (wildcards as whole labels, e.g. *.example.com): ${join(", ", [for h in keys(local.bypass.exclusions) : h if !can(regex("^(\\*\\.)*[a-z0-9_-]+(\\.[a-z0-9_*-]+)*$", h))])}"
  }
}

###############################################################################
# 1. SSL Decryption Exclusions (the "custom" half of the list Palo pre-populates)
#
# Traffic whose SNI or server cert CN matches is never decrypted and skips
# decryption policy entirely. No decryption log, no no-decrypt profile checks.
###############################################################################

resource "scm_decryption_exclusion" "this" {
  for_each = local.bypass.exclusions

  folder      = local.location.folder
  snippet     = local.location.snippet
  name        = each.key
  description = each.value
}

###############################################################################
# 2. Supporting objects for the no-decrypt policy rules
###############################################################################

resource "scm_tag" "bypass" {
  folder   = local.location.folder
  snippet  = local.location.snippet
  name     = var.name_prefix
  color    = "Orange"
  comments = "Managed by Terraform (panos-decrypt-bypass)"
}

resource "scm_url_category" "no_decrypt" {
  count = length(local.bypass.urls) > 0 ? 1 : 0

  folder      = local.location.folder
  snippet     = local.location.snippet
  name        = "${var.name_prefix}-urls"
  description = "Hostnames excluded from SSL decryption. Managed by Terraform from bypass/no-decrypt-urls.txt."
  type        = "URL List"
  list        = sort(keys(local.bypass.urls))
}

resource "scm_address" "destination" {
  for_each = local.addresses.destinations

  folder      = local.location.folder
  snippet     = local.location.snippet
  name        = each.value.name
  description = each.value.description
  ip_netmask  = each.value.ip_netmask
  ip_range    = each.value.ip_range
  fqdn        = each.value.fqdn
  tag         = [scm_tag.bypass.name]
}

resource "scm_address" "source" {
  for_each = local.addresses.sources

  folder      = local.location.folder
  snippet     = local.location.snippet
  name        = each.value.name
  description = each.value.description
  ip_netmask  = each.value.ip_netmask
  ip_range    = each.value.ip_range
  fqdn        = each.value.fqdn
  tag         = [scm_tag.bypass.name]
}

resource "scm_external_dynamic_list" "this" {
  for_each = var.edls

  folder  = local.location.folder
  snippet = local.location.snippet
  name    = each.key

  type = {
    url = each.value.type != "url" ? null : {
      url         = each.value.source_url
      description = each.value.description
      recurring = {
        five_minute = each.value.recurring == "five_minute" ? {} : null
        hourly      = each.value.recurring == "hourly" ? {} : null
      }
    }
    ip = each.value.type != "ip" ? null : {
      url         = each.value.source_url
      description = each.value.description
      recurring = {
        five_minute = each.value.recurring == "five_minute" ? {} : null
        hourly      = each.value.recurring == "hourly" ? {} : null
      }
    }
  }
}

resource "scm_decryption_profile" "no_decrypt" {
  count = var.create_no_decrypt_profile ? 1 : 0

  folder  = local.location.folder
  snippet = local.location.snippet
  name    = "${var.name_prefix}-no-decrypt"

  ssl_no_proxy = {
    block_expired_certificate = true
    block_untrusted_issuer    = true
  }
}
