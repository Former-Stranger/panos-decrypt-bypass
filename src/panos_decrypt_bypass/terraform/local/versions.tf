terraform {
  # 1.9+ for cross-variable validation.
  required_version = ">= 1.9"

  required_providers {
    panos = {
      source  = "PaloAltoNetworks/panos"
      version = "~> 2.0.14"
    }
  }
}

# Connection settings come from the environment (PANOS_HOSTNAME, PANOS_API_KEY,
# PANOS_PORT, PANOS_SKIP_VERIFY_CERTIFICATE), which the app fills in from
# FIREWALL_HOST, FIREWALL_API_KEY and FIREWALL_VERIFY_TLS.
provider "panos" {}
