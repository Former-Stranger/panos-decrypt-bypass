locals {
  location = {
    vsys = { name = var.vsys }
  }
}

# Decryption exclusions live in the firewall's device-wide SSL decryption
# settings, next to the forward trust certificates. Managing that block from
# here could overwrite them, so this module leaves exclusions alone.
check "exclusions_not_managed" {
  assert {
    condition     = length(local.bypass.exclusions) == 0
    error_message = "exclusion-hostnames.txt is ignored on locally managed firewalls. Move these entries to no-decrypt-urls.txt: ${join(", ", keys(local.bypass.exclusions))}"
  }
}

###############################################################################
# Supporting objects for the no-decrypt policy rules
###############################################################################

resource "panos_administrative_tag" "bypass" {
  location = local.location
  name     = var.name_prefix
  color    = "color6" # orange
  comments = "Managed by Terraform (panos-decrypt-bypass)"
}

resource "panos_custom_url_category" "no_decrypt" {
  count = length(local.bypass.urls) > 0 ? 1 : 0

  location    = local.location
  name        = "${var.name_prefix}-urls"
  description = "Hostnames excluded from SSL decryption. Managed by Terraform from bypass/no-decrypt-urls.txt."
  type        = "URL List"
  list        = sort(keys(local.bypass.urls))
}

resource "panos_address" "destination" {
  for_each = local.addresses.destinations

  location    = local.location
  name        = each.value.name
  description = each.value.description
  ip_netmask  = each.value.ip_netmask
  ip_range    = each.value.ip_range
  fqdn        = each.value.fqdn
  tags        = [panos_administrative_tag.bypass.name]
}

resource "panos_address" "source" {
  for_each = local.addresses.sources

  location    = local.location
  name        = each.value.name
  description = each.value.description
  ip_netmask  = each.value.ip_netmask
  ip_range    = each.value.ip_range
  fqdn        = each.value.fqdn
  tags        = [panos_administrative_tag.bypass.name]
}

resource "panos_external_dynamic_list" "this" {
  for_each = var.edls

  location = local.location
  name     = each.key

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

resource "panos_decryption_profile" "no_decrypt" {
  count = var.create_no_decrypt_profile ? 1 : 0

  location = local.location
  name     = "${var.name_prefix}-no-decrypt"

  ssl_no_proxy = {
    block_expired_certificate = true
    block_untrusted_issuer    = true
  }
}
