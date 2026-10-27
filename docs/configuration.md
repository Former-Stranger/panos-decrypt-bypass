# Configuration

There are three places to configure panos-decrypt-bypass:

| Where | What |
|---|---|
| [`.env`](#environment-variables) | Credentials, the login, log polling and container settings |
| [`data/terraform.tfvars`](#terraformtfvars) | Where the config lives (SCM folder or vsys), and what the no-decrypt rules match |
| [`data/bypass/*.txt`](#bypass-lists) | What's bypassed. Usually edited through the GUI or CLI. |

## Environment variables

Set these in `.env` (Docker Compose passes it to the container). Restart the
container after changing them: `docker compose up -d`.

### Web GUI

| Variable | Default | |
|---|---|---|
| `WEBGUI_PASSWORD` | (required) | Login password, at least 12 characters. Changing it signs everyone out. |
| `WEBGUI_AUTH` | `password` | `none` disables the login. Only do that if something in front of the app (such as your reverse proxy) requires a login. |
| `WEBGUI_SESSION_HOURS` | `12` | How long a login lasts. |
| `WEBGUI_COOKIE_SECURE` | `auto` | Mark the session cookie HTTPS-only. `auto` does so when the request (or `X-Forwarded-Proto`) is HTTPS. Set `true` behind an HTTPS proxy. |
| `WEBGUI_PORT` | `8088` | Host port in `compose.yaml`; the port `serve` listens on when run from source. |
| `WEBGUI_HOST` | `127.0.0.1` | Address `serve` listens on when run from source (the image uses `0.0.0.0`). |
| `WEBGUI_DEMO` | `false` | Sample logs and simulated deploys. Nothing is sent to SCM or a firewall. |
| `DOMAIN_LOOKUP` | `true` | Show **Look up** for a destination: registration (RDAP via rdap.org), DNS and the server's certificate. Lookups only run when clicked. `false` hides the button and blocks the API. |

### Management

| Variable | Default | |
|---|---|---|
| `MANAGEMENT` | `scm` | `scm` for a firewall managed by Strata Cloud Manager; `local` for a firewall configured on its own (not by SCM or Panorama). See [prerequisites](prerequisites.md). |

Keep one mode per data directory. The app refuses to run one mode against
Terraform state the other mode created, because Terraform would plan to delete
everything. To manage both kinds of firewall, run two containers with separate
data directories.

### Strata Cloud Manager (`MANAGEMENT=scm`)

| Variable | Default | |
|---|---|---|
| `SCM_CLIENT_ID` | (required) | Service account client ID. |
| `SCM_CLIENT_SECRET` | (required) | Service account secret. |
| `SCM_SCOPE` | (required) | `tsg_id:<your TSG ID>`. |
| `SCM_HOST` | `api.sase.paloaltonetworks.com` | SCM API host. |
| `SCM_AUTH_URL` | `https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token` | Token endpoint. |

### Firewall and log polling

| Variable | Default | |
|---|---|---|
| `FIREWALL_HOST` | (required) | Management address. Must match a name in its certificate. |
| `FIREWALL_API_KEY` | (required) | XML API key ([how to create one](prerequisites.md#2-firewall-xml-api-key)). |
| `FIREWALL_USERNAME` | (`local`: required) | The admin that owns `FIREWALL_API_KEY`. Commits include only this admin's changes. |
| `FIREWALL_TIMEZONE` | `UTC` | The timezone the firewall writes log timestamps in, e.g. `Europe/Berlin`. If it's wrong, "last seen" times are off. |
| `FIREWALL_CA_FILE` | (none) | CA certificate (path inside the container) that issued the management certificate, for a private CA. With `local`, Terraform trusts it too. |
| `FIREWALL_VERIFY_TLS` | `true` | Set `false` to skip certificate checks. Avoid it; use `FIREWALL_CA_FILE`. |
| `POLL_SECONDS` | `300` | How often to pull new logs. **Poll now** in the GUI fetches immediately. |
| `INITIAL_LOOKBACK_HOURS` | `24` | How far back the first poll reaches. |
| `RETENTION_DAYS` | `7` | How long logs are kept in the local database. |
| `FIREWALL_LOG_QUERY` | (none) | Extra PAN-OS log filter ANDed into every query, e.g. `(addr.src in 192.0.2.0/24)`. |

### Paths and container

| Variable | Default | |
|---|---|---|
| `DATA_DIR` | `/data` in the image, `./data` from source | The [data directory](installation.md#the-data-directory). |
| `PUID` / `PGID` | `1000` | User and group the container runs as, and owner of `./data`. |
| `PDB_VERSION` | `latest` | Image tag used by `compose.yaml`. |

## terraform.tfvars

`data/terraform.tfvars` holds your settings for the Terraform module. It's
created on first start from a commented template for your `MANAGEMENT` mode.
Changes take effect on the next deploy: use **Deploy…** in the GUI, which
shows the plan for review, or `panos-decrypt-bypass deploy`.

### Where the config lives: SCM

| Setting | Default | |
|---|---|---|
| `folder` | (set one) | SCM folder to create the bypass config in, as SCM shows it. The built-in *All Firewalls* folder is `ngfw-shared` in the API. |
| `snippet` | (set one) | A snippet to use instead of a folder. It must already be associated with the folders you push. |
| `push_folders` | `[folder]` | Folders to push after a deploy. Required with `snippet`. |
| `name_prefix` | `tf-ssl-bypass` | Prefix for everything created: rules, URL category, address objects, tag. |

Rules in parent folders are evaluated first. If a decrypt rule in a parent
folder matches the traffic you want to bypass, it wins over these no-decrypt
rules, so the bypass config has to live in that parent folder or above.

### Where the config lives: locally managed firewall

| Setting | Default | |
|---|---|---|
| `vsys` | `vsys1` | Virtual system for the objects and rules. |
| `name_prefix` | `tf-ssl-bypass` | Prefix for everything created: rules, URL category, address objects, tag. |

### What the no-decrypt rules match

| Setting | Default | |
|---|---|---|
| `from_zones` / `to_zones` | `["any"]` | Source and destination zones. |
| `source_addresses` | `["any"]` | Names of existing address objects or groups. The rule for `no-decrypt-sources.txt` uses its own list instead. |
| `services` | `["any"]` | `any` also catches TLS on ports other than 443. |
| `rule_placement` | top | Where the first rule goes, e.g. `{ relative_position = "after", target_rule = "My-Rule" }`. The others follow it in order. With `local` the rules are kept together as one block in that position, and moving them by hand shows up as a change on the next deploy. |
| `log_success` / `log_fail` | `true` | Log sessions the rules match. Undecrypted traffic is only logged when a decryption rule matches it. |
| `log_setting` | (none) | Log forwarding profile. |

### Decryption profile

| Setting | Default | |
|---|---|---|
| `no_decrypt_profile` | (none) | An existing decryption profile to attach. Its *No Decryption* settings apply to bypassed traffic. |
| `create_no_decrypt_profile` | `false` | Create a profile that blocks expired and untrusted server certificates on bypassed traffic. It's off by default because it can block the very sites you're bypassing (for example, ones with a private CA). |

### External dynamic lists

| Setting | Default | |
|---|---|---|
| `existing_url_edls` / `existing_ip_edls` | `[]` | Names of existing EDLs to add to the URL and destination rules. |
| `edls` | `{}` | EDLs to create: `{ name = { type = "url" or "ip", source_url = "...", recurring = "hourly" or "five_minute", description = "..." } }`. |

EDLs suit long or externally maintained lists: the firewall refreshes them
itself, without a push.

`bypass_dir` is set automatically; don't set it here.

## Bypass lists

`data/bypass/` holds one file per kind of bypass. The GUI and CLI edit them for
you. By hand: one entry per line, `#` starts a comment, and a comment after an
entry becomes that object's description.

| File | Becomes | Use for |
|---|---|---|
| `no-decrypt-urls.txt` | A custom URL category (URL List) and a no-decrypt rule | Hostnames. **The GUI's Bypass… button adds here.** |
| `no-decrypt-categories.txt` | A no-decrypt rule matching predefined URL categories | Broad carve-outs: `financial-services`, `health-and-medicine` |
| `no-decrypt-destinations.txt` | Address objects and a no-decrypt rule | Servers without a hostname (no SNI), whole ranges |
| `no-decrypt-sources.txt` | Address objects and a no-decrypt rule | Clients that can't trust your forward-trust CA: IoT, printers, guest networks |
| `no-decrypt-users.txt` | A no-decrypt rule matching users or groups | People or teams (needs User-ID) |
| `exclusion-hostnames.txt` | Custom decryption exclusions (SCM only) | Edited by hand only. Applies to every device, regardless of zones or source. Ignored with `local`, with a warning: exclusions live next to the forward-trust certificates in the firewall's SSL decryption settings, and the app doesn't touch those. Use `no-decrypt-urls.txt` instead. |

Each file's header explains its format. An empty list creates nothing, and the
rule for a list is removed when the list is emptied. Wildcard rules differ
between the URL list and the exclusion list; see
[How it works](how-it-works.md#matching-rules).

## Remote Terraform state

By default the state is a local file in `data/terraform/`. To keep it in a
remote backend, add a `backend.tf` to `data/terraform/`; the app never
overwrites files it didn't ship. For example:

```hcl
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "panos-decrypt-bypass/terraform.tfstate"
    region = "eu-central-1"
  }
}
```

Then migrate once:
`docker compose exec panos-decrypt-bypass sh -c 'cd /data/terraform && terraform init -migrate-state'`.
Give the container the backend's credentials through `.env`.
