# How it works

## The pieces

```
firewall management ──XML API──► poller ──► SQLite ──► web GUI ◄── you
                                                          │ Bypass…
                                                          ▼
                    bypass lists + terraform.tfvars ──► Terraform
                                                          │
                       ┌──────────────────────────────────┴───────────────┐
                       ▼ MANAGEMENT=scm (scm provider)                    ▼ MANAGEMENT=local (panos provider)
      Strata Cloud Manager (candidate config)             the firewall (candidate config)
                       │ push (SCM API)                                   │ commit (XML API)
                       ▼                                                  ▼
                   firewalls                                        running config
```

- **Poller:** every `POLL_SECONDS` it asks the firewall's XML API for
  decryption logs since the newest one stored (`type=log&log-type=decryption`),
  keeps them for `RETENTION_DAYS`, and groups failures by destination.
- **Bypass lists:** plain text files, one per kind of bypass. They're the
  source of truth; the GUI and CLI only edit them.
- **Terraform:** a bundled module turns the lists and your `terraform.tfvars`
  into objects. With `MANAGEMENT=scm` they're SCM objects, through the
  [PaloAltoNetworks/scm](https://registry.terraform.io/providers/PaloAltoNetworks/scm)
  provider. With `MANAGEMENT=local` they're created on the firewall in a vsys,
  through the
  [PaloAltoNetworks/panos](https://registry.terraform.io/providers/PaloAltoNetworks/panos)
  provider. Both modules parse the lists the same way. State lives in your
  data directory.
- **Push (SCM):** the app pushes through SCM's API
  (`POST /config/operations/v1/config-versions/candidate:push`) and follows the
  job and each firewall's child job to the end. Pushes include only the service
  account's own changes, so other admins' unfinished edits never go out.
- **Commit (local):** the app starts a partial commit over the XML API with
  only `FIREWALL_USERNAME`'s changes, then follows the commit job to the end,
  so other admins' unfinished edits never go live with a bypass.

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
changes, deletions, and drift (someone edited the objects by hand). With
`local`, all the no-decrypt rules are one Terraform resource, so a change to it
is applied without review only if it adds the URL rule and leaves every other
rule, and their position, exactly as they were.
Cancelling a review removes the entries that were just added, so the lists and
the config stay in step. Only one deploy runs at a time.

## Terraform details

- The image ships Terraform and both providers in a local mirror, so
  `terraform init` never contacts the registry at runtime.
- Before every run the module for your `MANAGEMENT` mode is copied into
  `data/terraform/` with your `terraform.tfvars`. Files you add there
  yourself, such as `backend.tf`, are kept.
- With `local`, the app passes `FIREWALL_HOST`, `FIREWALL_API_KEY` and
  `FIREWALL_VERIFY_TLS` to the provider as `PANOS_*` variables. The provider
  has no CA setting, so for `FIREWALL_CA_FILE` the app writes a bundle of the
  system roots plus your CA to `data/terraform/.ca-bundle.pem` and points
  `SSL_CERT_FILE` at it.
- With `local`, decryption exclusions aren't managed: the provider can only
  manage them through the firewall's whole SSL decryption settings, forward
  trust certificates included.
- The provider now also offers a native `scm_config_push` action. The app
  keeps using the API push for now, because it reports each firewall's result
  and scopes pushes to the service account.
