# Using panos-decrypt-bypass

## The web GUI

![Dashboard](images/dashboard.jpg)

The dashboard lists every destination with decryption failures in the chosen
window, newest first. A destination is the TLS hostname (SNI), or the server
certificate's name if there's no SNI, or the IP address if there's neither.

| Column | |
|---|---|
| **Last seen** | Most recent failure. Hover for the exact time. |
| **Destination** | Hostname and port. A trailing `…` means the firewall's log cut the name short (see [below](#truncated-hostnames)). |
| **Destination IP** | Every IP seen for it (CDNs often have many). Hover for the full list. |
| **Problem** | A plain-English diagnosis and the raw error. |
| **Hits / Clients** | Failed sessions and distinct client IPs. Hover *Clients* for the IPs. |
| **Decrypt rule** | The decryption rule that tried to decrypt it. |
| **Bypass** | **Bypass…**, or ✓ and the list entry that already covers it. |

Filters: the time window, a search box (hostname, client or destination IP,
user, error text), **Failures only** (untick to also see successful sessions,
including traffic your bypasses match), and **Hide already bypassed**.
**Poll now** fetches new logs immediately instead of waiting for the next
poll (every 5 minutes by default).

Click a row to see its individual sessions: time, client, user and host,
destination, error, proxy type and TLS version.

![Session details](images/sessions.jpg)

### What the diagnoses mean

| Diagnosis | Usually means | Bypass? |
|---|---|---|
| **Client rejected the firewall's certificate** | The app pins its certificate, or this device doesn't trust your forward-trust CA. If the device trusts the CA for other sites, it's pinning. | Yes, if it's pinning. Otherwise install your CA on the device. |
| **Firewall doesn't trust the server's certificate chain** | The site uses its own private CA, or the firewall is missing a public intermediate or root CA. | For private-CA sites, yes. For a missing public CA, import it on the firewall instead. |
| **Server certificate problem** | Expired, self-signed or incomplete server certificate. | Only for sites you trust; a bypass hides the problem from users. |
| **Firewall can't negotiate with the server** | TLS version, cipher, client certificates or an oversized chain that the decryption profile can't handle. | Usually yes. |
| **Firewall ran out of decryption resources** | A capacity problem on the firewall. | No; fix the capacity. |
| **Session resumption failed** | Usually harmless; the client retries. | No. |

When the same error appears across many unrelated sites, the cause is likely
the decryption profile or firewall, not the sites.

### What is this destination?

Expand a row to see **About this destination**:

- **Seen from** lists the clients that hit it in the time window (IP, host
  name, user, zone, number of events). Often the quickest clue: an unfamiliar
  domain reached only from a laptop is usually an app on that laptop.
- **Look up** fetches, on demand:
  - **Registration:** the registered domain, registrant (often hidden for
    privacy), registrar, dates and name servers, from RDAP. For an IP
    address, the network's owner and range.
  - **DNS:** the canonical name and addresses. A canonical name like
    `*.akamai.net` or `*.cloudfront.net` shows the CDN in front of it.
  - **Server certificate:** subject, organization, issuer, and the other
    names it covers. Related domains on the certificate often name the
    product.
  - **Research links** to VirusTotal, urlscan.io, crt.sh and a web search.

**Find the app on the client** gives two commands for macOS, Windows or
Linux, filled in for this destination. Run them on a client from *Seen from*:

- **Search installed apps** for the name. Apps that talk to a backend
  usually have its name built in, so this finds unfamiliar domains that no
  public source explains (for example an alternate API domain that turned out
  to belong to a 3D printer's slicer app). After **Look up**, it searches for
  the registered domain, which also catches other subdomains. Apps that
  compress or encrypt their files won't match.
- **Which process is connected right now** to the destination's IPs, using
  `lsof`, `Get-NetTCPConnection` or `ss`. Run it while the app is active.

Hostnames in decryption logs come from the client's TLS handshake, so the
page only builds a command from a name made of letters, digits, dots and
hyphens, and from well-formed IP addresses. Anything else gets no command.
Click a command to copy it.

Lookups send the name to rdap.org (which forwards to the domain's registry)
and connect to the destination on port 443; private addresses are never
contacted. Results are kept for a day. Set `DOMAIN_LOOKUP=false` to turn it
off.

### Copying values

Click any value in the details or the events table to copy it; *Copied*
confirms. Clicking a destination copies just the IP, without the port. You
can also focus a value with Tab and press Enter.

### Bypassing a destination

Click **Bypass…**:

![Bypass dialog](images/bypass-dialog.jpg)

1. Choose **what to bypass**: only that hostname; the hostname and its
   subdomains; or the whole domain (e.g. `example.com` and `*.example.com`).
   *Will add* shows exactly what goes into the list, and you can edit the
   hostnames before adding.
2. Optionally change the description, which is stored with each entry and
   shown on the URL category.
3. Click **Add & deploy**.

The deploy panel then shows each step: plan, apply, then push to firewall
(SCM) or commit (locally managed firewall).

![Finished deploy](images/deploy-done.jpg)

- **Applied without asking** only when the plan changes nothing but the
  no-decrypt URL list (and, the first time, creates its rule).
- **Stops for review** if anything else would change: other rules, settings
  you edited in `terraform.tfvars`, deletions, or changes someone made by
  hand. It lists every change: **Apply & push** (or **Apply & commit**)
  continues, **Cancel** takes your new entries back out of the list, and
  **Later** leaves the review waiting.
- If **the push or commit fails**, the change is already in SCM or the
  firewall's candidate config. **Retry push** (**Retry commit**) tries again
  without re-applying.

You can close the panel while a deploy runs; a banner at the top shows its
progress. Only one deploy runs at a time.

Destinations with no hostname can't go in the URL list (the button is greyed
out). Add their IP from the CLI: `panos-decrypt-bypass add destination 203.0.113.50`.

### Deploy…

**Deploy…** (top right) plans whatever is pending, such as edits to
`terraform.tfvars` or lists you changed by hand, and always stops for review. If
there's nothing to apply but an earlier push or commit failed, it offers
**Push to firewall** (**Commit now**).

### Truncated hostnames

Decryption logs store at most 31 characters of the hostname, plus its real
length. When the server certificate's name is exactly that long and starts the
same way, the viewer uses it. Otherwise it shows the cut-off name with `…`, and
the bypass dialog asks you to complete it before adding.

## The command line

In Docker, prefix commands with `docker compose exec panos-decrypt-bypass`.

| Command | |
|---|---|
| `panos-decrypt-bypass` | Interactive menu: add, remove, list, plan, deploy |
| `panos-decrypt-bypass add url example.org --subdomains -d "Vendor app"` | Add entries. Kinds: `url`, `category`, `destination`, `source`, `user`. |
| `panos-decrypt-bypass remove url example.org` | Remove entries (also `exclusion`) |
| `panos-decrypt-bypass list [kind]` | Show the lists |
| `panos-decrypt-bypass plan` | Show what would change (read-only) |
| `panos-decrypt-bypass deploy` | Plan, confirm, apply, then push or commit and wait for the result |
| `panos-decrypt-bypass deploy --no-push` | Apply only; push or commit later |
| `panos-decrypt-bypass push` (or `commit`) | Push or commit without applying (e.g. retry a failed one) |
| `panos-decrypt-bypass terraform <args>` | Run any Terraform command (`destroy`, `import`, `state list`, …) with the app's settings |
| `panos-decrypt-bypass init` | Create the data directory and starter files |
| `panos-decrypt-bypass serve` | Run the web GUI |
| `panos-decrypt-bypass version` | Print the version |

`add` and `remove` only edit the lists; add `--deploy` to deploy straight away.
Entries are cleaned up as they're added: pasted URLs become hostnames, case and
trailing slashes are normalised, and duplicates are skipped. `--subdomains`
turns `www.example.org` into `example.org` and `*.example.org`.

`deploy` and `push` only include the SCM service account's own changes, or
`FIREWALL_USERNAME`'s on a locally managed firewall. Add `--all-admins` to
push or commit everything that's pending.
