# How it works

## The pieces

```
firewall management ──XML API──► poller ──► SQLite ──► web GUI ◄── you
                                                          │ Bypass…
                                                          ▼
                    bypass lists + terraform.tfvars ──► Terraform (scm provider)
                                                          │
                                                          ▼
                                   Strata Cloud Manager (candidate config)
                                                          │ push (SCM API)
                                                          ▼
                                                      firewalls
```

- **Poller:** every `POLL_SECONDS` it asks the firewall's XML API for
  decryption logs since the newest one stored (`type=log&log-type=decryption`),
  keeps them for `RETENTION_DAYS`, and groups failures by destination.
- **Bypass lists:** plain text files, one per kind of bypass. They're the
  source of truth; the GUI and CLI only edit them.
- **Terraform:** a bundled module turns the lists and your `terraform.tfvars`
  into SCM objects with the
  [PaloAltoNetworks/scm](https://registry.terraform.io/providers/PaloAltoNetworks/scm)
  provider. State lives in your data directory.
- **Push:** the app pushes through SCM's API
  (`POST /config/operations/v1/config-versions/candidate:push`) and follows the
  job and each firewall's child job to the end. Pushes include only the service
  account's own changes, so other admins' unfinished edits never go out.

## Two ways to bypass decryption

PAN-OS has two families of bypass, and they behave differently.

### Decryption exclusions (technical)

- **Predefined:** Palo Alto Networks maintains a list of sites known to break
  decryption and updates it through content updates. Terraform can't change
  it. A custom entry with the same hostname takes precedence.
- **Custom:** `exclusion-hostnames.txt`. The firewall matches the TLS **SNI or
  the server certificate's CN**.
- **Local exclusion cache:** when a session fails decryption for a technical
  reason and the decryption profile allows it, the firewall excludes that
  server for 12 hours by itself. There's nothing to configure, but it explains
  failures that "fix themselves".
- Excluded traffic **skips decryption policy entirely**: no decryption logs,
  no certificate checks, and it applies to **every device**.

### No-decrypt rules (policy)

- Decryption rules with action `no-decrypt`, matching zones, addresses, users,
  services, URL categories (predefined, custom URL lists, URL EDLs) and IP EDLs.
- They're logged and scoped: only traffic matching the zones and sources you
  configure is bypassed.
- A decryption profile can still check certificates on bypassed traffic (the
  checks can't see TLS 1.3 certificates, which are encrypted).

**This project defaults to no-decrypt rules**: the GUI and `add` only write
to them. Exclusions are left for hand-edited, technical cases.

### Rule order

Following Palo Alto Networks' guidance, the rules go at the top of the
decryption pre-rulebase (or wherever `rule_placement` says), in this order:

1. destinations (IP exceptions)
2. sources
3. users
4. hostnames (URL list and URL EDLs)
5. predefined URL categories

Each list gets its own rule (`tf-ssl-bypass-destinations`, `-urls`, …), so
the rule name in a log tells you why a session wasn't decrypted.

## Matching rules

Before decryption the firewall only sees the **SNI**, never the URL path, so
paths are dropped when you add an entry.

| Entry | URL list (no-decrypt rule) | Exclusion list |
|---|---|---|
| `example.com` | `example.com` only | `example.com` only |
| `*.example.com` | Subdomains at **any depth**: `a.example.com`, `a.b.example.com` | **One** label only: `a.example.com`, not `a.b.example.com` |
| Covers `example.com` itself? | No, add both | No, add both |

That's why "include subdomains" adds both `example.com` and `*.example.com`.

Decryption rules can't match App-ID (the firewall decides whether to decrypt
before it identifies the app), so bypasses are always by hostname, address,
category or user.

## Deploy safety

A one-click bypass runs `terraform plan`, then applies without asking only if
every change is one of:

- an update to the no-decrypt URL list, or
- creating that list and its rule (the first bypass).

Anything else stops for review. That includes changes to other rules, profile
changes, deletions, and drift (someone edited the objects in SCM by hand).
Cancelling a review removes the entries that were just added, so the lists and
SCM stay in step. Only one deploy runs at a time.

## Terraform details

- The image ships Terraform and the SCM provider in a local mirror, so
  `terraform init` never contacts the registry at runtime.
- Before every run the bundled module is copied into `data/terraform/` with
  your `terraform.tfvars`. Files you add there yourself, such as `backend.tf`,
  are kept.
- The provider now also offers a native `scm_config_push` action. The app
  keeps using the API push for now, because it reports each firewall's result
  and scopes pushes to the service account.
