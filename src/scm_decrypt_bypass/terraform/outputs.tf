output "push_folders" {
  description = "Folders to push after apply."
  value       = coalesce(var.push_folders, compact([var.folder]))
}

output "summary" {
  description = "What is currently bypassed."
  value = {
    decryption_exclusions = sort(keys(local.bypass.exclusions))
    no_decrypt_rules      = [for k in local.enabled_rules : "${var.name_prefix}-${k}"]
    no_decrypt_urls       = sort(keys(local.bypass.urls))
    no_decrypt_categories = sort(keys(local.bypass.categories))
    no_decrypt_dsts       = sort(keys(local.bypass.destinations))
    no_decrypt_srcs       = sort(keys(local.bypass.sources))
    no_decrypt_users      = sort(keys(local.bypass.users))
  }
}
