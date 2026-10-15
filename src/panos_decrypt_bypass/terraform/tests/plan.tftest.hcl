# Offline plan against a mocked SCM provider. From the repo root:
#   terraform -chdir=src/panos_decrypt_bypass/terraform init -backend=false
#   terraform -chdir=src/panos_decrypt_bypass/terraform test
# Uses the lists in tests/fixtures instead of a data directory.

mock_provider "scm" {}

variables {
  folder     = "ngfw-shared"
  bypass_dir = "../../../tests/fixtures/bypass"
}

run "parses_lists_and_builds_objects" {
  command = plan

  assert {
    condition     = toset(keys(scm_decryption_exclusion.this)) == toset(["pinned.example.com", "*.mtls.example.com"])
    error_message = "Exclusions should be lowercased and de-duplicated."
  }
  assert {
    condition     = scm_decryption_exclusion.this["pinned.example.com"].description == "pinned cert"
    error_message = "Inline comment should become the description."
  }
  assert {
    condition     = scm_url_category.no_decrypt[0].list == tolist(["*.mybank.com", "benefits.example-hr.com", "mybank.com"])
    error_message = "URL list should be normalised (scheme and trailing slash stripped, lowercase, sorted)."
  }
  assert {
    condition     = scm_address.destination["203.0.113.10-203.0.113.20"].ip_range == "203.0.113.10-203.0.113.20"
    error_message = "IP ranges should become ip_range address objects."
  }
  assert {
    condition     = scm_address.destination["cafe.be"].fqdn == "cafe.be"
    error_message = "Hostnames should become fqdn address objects."
  }
  assert {
    condition     = scm_address.destination["2001:db8::/32"].ip_netmask == "2001:db8::/32"
    error_message = "IPv6 CIDRs should become ip_netmask address objects."
  }
}

run "chains_rules_in_order" {
  command = plan

  assert {
    condition     = length(module.rule_destinations) == 1 && length(module.rule_sources) == 1 && length(module.rule_users) == 1 && length(module.rule_urls) == 1 && length(module.rule_categories) == 1
    error_message = "Every non-empty list should produce a rule."
  }
  assert {
    condition     = local.rule_placement.destinations.relative_position == "top"
    error_message = "First rule should go to the top."
  }
  assert {
    condition     = local.rule_placement.categories.target_rule == "tf-ssl-bypass-urls"
    error_message = "Each rule should be placed after the previous one."
  }
  assert {
    condition     = jsonencode([local.rules.users.source_user, local.rules.users.category]) == jsonencode([["EXAMPLE\\CEO"], ["any"]])
    error_message = "User rule should keep case and match any category, got ${jsonencode([local.rules.users.source_user, local.rules.users.category])}."
  }
}

run "skips_empty_rules_and_rechains" {
  command = plan

  variables {
    bypass_dir = "../../../tests/fixtures/empty"
  }

  assert {
    condition     = length(module.rule_destinations) + length(module.rule_urls) == 0 && length(scm_url_category.no_decrypt) == 0
    error_message = "Empty lists should create nothing."
  }
}

run "edls_feed_rules" {
  command = plan

  variables {
    bypass_dir                = "../../../tests/fixtures/empty"
    create_no_decrypt_profile = true
    edls = {
      tf-edl-urls = { type = "url", source_url = "https://example.com/urls.txt" }
      tf-edl-ips  = { type = "ip", source_url = "https://example.com/ips.txt", recurring = "five_minute" }
    }
  }

  assert {
    condition     = jsonencode(local.enabled_rules) == jsonencode(["destinations", "urls"])
    error_message = "EDLs alone should enable the destination and URL rules, got ${jsonencode(local.enabled_rules)}."
  }
  assert {
    condition     = jsonencode([local.rules.urls.category, local.rules.destinations.destination]) == jsonencode([["tf-edl-urls"], ["tf-edl-ips"]])
    error_message = "URL EDLs go in category, IP EDLs in destination, got ${jsonencode([local.rules.urls.category, local.rules.destinations.destination])}."
  }
  assert {
    condition     = local.rules.urls.relative_position == "after" && local.rules.urls.target_rule == "tf-ssl-bypass-destinations"
    error_message = "URL rule should chain after the destination rule."
  }
  assert {
    condition     = local.rules.urls.profile == "tf-ssl-bypass-no-decrypt"
    error_message = "Created no-decrypt profile should be attached."
  }
}

run "zones_and_source_object_apply_to_rules" {
  command = plan

  variables {
    from_zones       = ["trust"]
    to_zones         = ["untrust"]
    source_addresses = ["laptop-jdoe"]
  }

  assert {
    condition = alltrue([
      for k in ["destinations", "users", "urls", "categories"] :
      jsonencode([local.rules[k].from, local.rules[k].to, local.rules[k].source]) == jsonencode([["trust"], ["untrust"], ["laptop-jdoe"]])
    ])
    error_message = "Rules should use the configured zones and source object, got ${jsonencode({ for k, r in local.rules : k => [r.from, r.to, r.source] })}."
  }
  assert {
    condition     = jsonencode(local.rules.sources.source) == jsonencode(["tf-ssl-bypass-src-10.20.30.0_24"])
    error_message = "The sources rule should keep the addresses from its own list."
  }
}
