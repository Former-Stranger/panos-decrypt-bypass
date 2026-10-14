terraform {
  # 1.9+ for cross-variable validation.
  required_version = ">= 1.9"

  required_providers {
    scm = {
      source  = "PaloAltoNetworks/scm"
      version = "~> 1.0.13"
    }
  }
}

# Credentials come from the environment (SCM_CLIENT_ID, SCM_CLIENT_SECRET,
# SCM_SCOPE, and optionally SCM_HOST / SCM_AUTH_URL), the same variables the
# app's own SCM API calls use.
provider "scm" {}
