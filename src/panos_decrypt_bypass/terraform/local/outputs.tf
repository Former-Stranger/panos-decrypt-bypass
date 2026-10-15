output "vsys" {
  description = "Virtual system the bypass config lives in."
  value       = var.vsys
}

output "summary" {
  description = "What is currently bypassed."
  value = {
    no_decrypt_rules      = [for k in local.enabled_rules : "${var.name_prefix}-${k}"]
    no_decrypt_urls       = sort(keys(local.bypass.urls))
    no_decrypt_categories = sort(keys(local.bypass.categories))
    no_decrypt_dsts       = sort(keys(local.bypass.destinations))
    no_decrypt_srcs       = sort(keys(local.bypass.sources))
    no_decrypt_users      = sort(keys(local.bypass.users))
  }
}
