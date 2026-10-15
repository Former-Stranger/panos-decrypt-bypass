# Offline plan against a mocked PAN-OS provider. From the repo root:
#   terraform -chdir=src/panos_decrypt_bypass/terraform/local init -backend=false
#   terraform -chdir=src/panos_decrypt_bypass/terraform/local test
# Uses the lists in tests/fixtures instead of a data directory.

mock_provider "panos" {}

variables {
  bypass_dir = "../../../../tests/fixtures/bypass"
}

run "builds_objects_in_vsys" {
  command = plan

  # The fixture lists include exclusions, which this module ignores (warning).
  expect_failures = [check.exclusions_not_managed]

  assert {
    condition     = panos_custom_url_category.no_decrypt[0].list == tolist(["*.mybank.com", "benefits.example-hr.com", "mybank.com"])
    error_message = "URL list should be normalised (scheme and trailing slash stripped, lowercase, sorted)."
  }
  assert {
    condition     = panos_custom_url_category.no_decrypt[0].location.vsys.name == "vsys1"
    error_message = "Objects should default to vsys1."
  }
  assert {
    condition     = panos_address.destination["203.0.113.10-203.0.113.20"].ip_range == "203.0.113.10-203.0.113.20"
    error_message = "IP ranges should become ip_range address objects."
  }
  assert {
    condition     = panos_address.destination["cafe.be"].fqdn == "cafe.be"
    error_message = "Hostnames should become fqdn address objects."
  }
  assert {
    condition     = panos_address.source["10.20.30.0/24"].tags == tolist(["tf-ssl-bypass"])
    error_message = "Address objects should carry the bypass tag."
  }
}

run "rules_in_order_at_top" {
  command         = plan
  expect_failures = [check.exclusions_not_managed]

  assert {
    condition     = [for r in panos_decryption_policy_rules.no_decrypt[0].rules : r.name] == ["tf-ssl-bypass-destinations", "tf-ssl-bypass-sources", "tf-ssl-bypass-users", "tf-ssl-bypass-urls", "tf-ssl-bypass-categories"]
    error_message = "Every non-empty list should produce a rule, in order."
  }
  assert {
    condition     = panos_decryption_policy_rules.no_decrypt[0].position.where == "first" && panos_decryption_policy_rules.no_decrypt[0].position.pivot == null
    error_message = "Rules should go to the top by default."
  }
  assert {
    condition     = alltrue([for r in panos_decryption_policy_rules.no_decrypt[0].rules : r.action == "no-decrypt"])
    error_message = "Every rule should be no-decrypt."
  }
  assert {
    condition     = jsonencode([local.rules.users.source_user, local.rules.users.category]) == jsonencode([["EXAMPLE\\CEO"], ["any"]])
    error_message = "User rule should keep case and match any category."
  }
  assert {
    condition     = local.rules.urls.category == ["tf-ssl-bypass-urls"]
    error_message = "URL rule should use the custom URL category."
  }
}

run "skips_empty_rules" {
  command = plan

  variables {
    bypass_dir = "../../../../tests/fixtures/empty"
  }

  assert {
    condition     = length(panos_decryption_policy_rules.no_decrypt) + length(panos_custom_url_category.no_decrypt) + length(panos_address.destination) == 0
    error_message = "Empty lists should create nothing but the tag."
  }
}

run "placement_edls_and_profile" {
  command = plan

  variables {
    bypass_dir                = "../../../../tests/fixtures/empty"
    vsys                      = "vsys2"
    create_no_decrypt_profile = true
    rule_placement            = { relative_position = "after", target_rule = "Allow-Infra" }
    edls = {
      tf-edl-urls = { type = "url", source_url = "https://example.com/urls.txt" }
      tf-edl-ips  = { type = "ip", source_url = "https://example.com/ips.txt", recurring = "five_minute" }
    }
  }

  assert {
    condition     = [for r in panos_decryption_policy_rules.no_decrypt[0].rules : r.name] == ["tf-ssl-bypass-destinations", "tf-ssl-bypass-urls"]
    error_message = "EDLs alone should enable the destination and URL rules."
  }
  assert {
    condition     = jsonencode([local.rules.urls.category, local.rules.destinations.destination_addresses]) == jsonencode([["tf-edl-urls"], ["tf-edl-ips"]])
    error_message = "URL EDLs go in category, IP EDLs in destination."
  }
  assert {
    condition     = jsonencode(panos_decryption_policy_rules.no_decrypt[0].position) == jsonencode({ directly = true, pivot = "Allow-Infra", where = "after" })
    error_message = "rule_placement should map to the provider's position."
  }
  assert {
    condition     = local.rules.urls.profile == "tf-ssl-bypass-no-decrypt" && panos_decryption_profile.no_decrypt[0].location.vsys.name == "vsys2"
    error_message = "Created no-decrypt profile should be attached, in the chosen vsys."
  }
}

run "zones_and_source_object_apply_to_rules" {
  command         = plan
  expect_failures = [check.exclusions_not_managed]

  variables {
    from_zones       = ["trust"]
    to_zones         = ["untrust"]
    source_addresses = ["laptop-jdoe"]
  }

  assert {
    condition = alltrue([
      for k in ["destinations", "users", "urls", "categories"] :
      jsonencode([local.rules[k].source_zones, local.rules[k].destination_zones, local.rules[k].source_addresses]) == jsonencode([["trust"], ["untrust"], ["laptop-jdoe"]])
    ])
    error_message = "Rules should use the configured zones and source object."
  }
  assert {
    condition     = jsonencode(local.rules.sources.source_addresses) == jsonencode(["tf-ssl-bypass-src-10.20.30.0_24"])
    error_message = "The sources rule should keep the addresses from its own list."
  }
}
