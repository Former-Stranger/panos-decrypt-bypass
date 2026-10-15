# Shared by the scm and local modules: keep both copies identical
# (tests/test_terraform_modules.py checks).

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
