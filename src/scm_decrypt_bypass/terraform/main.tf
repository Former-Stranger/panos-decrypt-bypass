###############################################################################
# Parse the bypass list files.
#
# Each file holds one entry per line. Anything after "#" is a comment; a
# comment on the same line as an entry becomes that entry's description where
# the object supports one. Blank lines are ignored, duplicates are merged.
###############################################################################

locals {
  bypass_files = {
    exclusions   = "exclusion-hostnames.txt"
    urls         = "no-decrypt-urls.txt"
    categories   = "no-decrypt-categories.txt"
    destinations = "no-decrypt-destinations.txt"
    sources      = "no-decrypt-sources.txt"
    users        = "no-decrypt-users.txt"
  }

  bypass_lines = {
    for kind, file in local.bypass_files : kind => [
      for line in split("\n", fileexists("${var.bypass_dir}/${file}") ? file("${var.bypass_dir}/${file}") : "") : {
        entry       = trimspace(split("#", line)[0])
        description = trimspace(join("#", slice(split("#", line), 1, length(split("#", line)))))
      } if trimspace(split("#", line)[0]) != ""
    ]
  }

  # Hostnames are case-insensitive; user/group names are left as written.
  # Scheme and trailing slash are stripped so pasted URLs still work.
  bypass_grouped = {
    for kind, lines in local.bypass_lines : kind => {
      for l in lines :
      (kind == "users" ? l.entry : trimsuffix(replace(lower(l.entry), "/^https?:\\/\\//", ""), "/")) => l.description...
    }
  }

  bypass = {
    for kind, entries in local.bypass_grouped : kind => {
      for entry, descriptions in entries : entry => try(compact(descriptions)[0], null)
    }
  }

  ipv4_re  = "[0-9]{1,3}(\\.[0-9]{1,3}){3}"
  ipv6_re  = "[0-9a-f]*:[0-9a-f:.]*"
  cidr_re  = "^(${local.ipv4_re}|${local.ipv6_re})(/[0-9]{1,3})?$"
  range_re = "^(${local.ipv4_re}|${local.ipv6_re})-(${local.ipv4_re}|${local.ipv6_re})$"

  # Destination and source entries become address objects: IP/CIDR, IP range, or FQDN.
  addresses = {
    for side in ["destinations", "sources"] : side => {
      for entry, description in local.bypass[side] : entry => {
        name        = substr("${var.name_prefix}-${side == "destinations" ? "dst" : "src"}-${replace(replace(entry, "/", "_"), ":", ".")}", 0, 63)
        description = description
        ip_netmask  = can(regex(local.cidr_re, entry)) ? entry : null
        ip_range    = can(regex(local.range_re, entry)) ? entry : null
        fqdn        = !can(regex(local.cidr_re, entry)) && !can(regex(local.range_re, entry)) ? entry : null
      }
    }
  }

  location = {
    folder  = var.folder
    snippet = var.snippet
  }
}

###############################################################################
# Sanity checks. These warn at plan time rather than fail.
###############################################################################

check "url_entries_are_hostnames" {
  assert {
    condition     = alltrue([for u in keys(local.bypass.urls) : !strcontains(u, "/")])
    error_message = "no-decrypt-urls.txt has entries with a path. Decryption rules only see the hostname (SNI), so anything after the first \"/\" never matches: ${join(", ", [for u in keys(local.bypass.urls) : u if strcontains(u, "/")])}"
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
  comments = "Managed by Terraform (scm-decrypt-bypass)"
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
