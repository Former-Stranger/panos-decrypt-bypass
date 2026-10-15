# panos-decrypt-bypass settings. Lives in your data directory (DATA_DIR,
# /data in the container); edit it, then use Deploy… in the web GUI or
# `panos-decrypt-bypass deploy`. Every setting is described in variables.tf
# and in docs/configuration.md.

# --- Where the config lives in Strata Cloud Manager (required) ---------------
# Set exactly one of folder or snippet. Use the folder name as SCM shows it;
# the built-in "All Firewalls" folder is "ngfw-shared" in the API.
# folder = "ngfw-shared"

# Or put everything in a snippet, and list the folders to push:
# snippet      = "ssl-bypass"
# push_folders = ["Branch Firewalls"]

# --- What the no-decrypt rules match -------------------------------------------
# Zones, source addresses and services for every no-decrypt rule. "any" is the
# safe default for no-decrypt; narrow them to limit who gets bypassed.
# from_zones       = ["trust"]
# to_zones         = ["untrust"]
# source_addresses = ["my-laptop"]   # existing SCM address objects or groups
# services         = ["any"]

# Rules go to the top of the decryption pre-rulebase by default. To slot them
# under an existing rule instead:
# rule_placement = { relative_position = "after", target_rule = "My-Existing-Rule" }

# --- Decryption profile ------------------------------------------------------
# Attach an existing decryption profile to every no-decrypt rule (its
# "No Decryption" settings apply to bypassed traffic)...
# no_decrypt_profile = "My-Decryption-Profile"
# ...or have Terraform create one that blocks expired and untrusted certs:
# create_no_decrypt_profile = true

# --- Logging -------------------------------------------------------------------
# log_setting = "my-log-forwarding-profile"

# --- External dynamic lists ------------------------------------------------------
# Reference existing EDLs...
# existing_url_edls = ["corp-no-decrypt-urls"]
# existing_ip_edls  = ["corp-no-decrypt-ips"]
# ...or create them:
# edls = {
#   "ssl-bypass-vendor-urls" = {
#     type        = "url"
#     source_url  = "https://example.com/no-decrypt-urls.txt"
#     recurring   = "hourly"
#     description = "Vendor-maintained bypass list"
#   }
# }
