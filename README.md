# scm-decrypt-bypass

[![CI](https://github.com/Former-Stranger/scm-decrypt-bypass/actions/workflows/ci.yml/badge.svg)](https://github.com/Former-Stranger/scm-decrypt-bypass/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Former-Stranger/scm-decrypt-bypass)](https://github.com/Former-Stranger/scm-decrypt-bypass/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Find TLS decryption failures on Palo Alto Networks firewalls managed by
Strata Cloud Manager, and bypass them in one click.**

> [!IMPORTANT]
> **Requires firewalls managed by Strata Cloud Manager (SCM).** Bypasses are
> created and pushed through SCM, so firewalls managed by Panorama or locally
> aren't supported. The Docker host also needs HTTPS access to the firewall's
> management interface to read decryption logs.

SSL/TLS decryption breaks some apps: ones that pin their certificates, use
client certificates, or speak TLS the firewall can't proxy. Finding them
means digging through decryption logs, and fixing them means editing
decryption policy and pushing config. scm-decrypt-bypass does both:

- a **web GUI** that pulls decryption logs from the firewall, groups the
  failures by destination and explains each one in plain English;
- a **Bypass…** button that adds the hostname to a no-decrypt URL category,
  applies it in Strata Cloud Manager (SCM) with Terraform and pushes it to the
  firewall, showing every step;
- a **CLI** and plain-text bypass lists for everything else: URL categories,
  source and destination addresses, users and external dynamic lists.

![Dashboard showing decryption failures grouped by destination](docs/images/dashboard.jpg)

| Session details | One-click bypass | Deploy result |
|---|---|---|
| ![Expanded row with individual sessions](docs/images/sessions.jpg) | ![Bypass dialog](docs/images/bypass-dialog.jpg) | ![Finished deploy](docs/images/deploy-done.jpg) |

*Screenshots use the built-in demo data.*

## How it works

```
firewall ──XML API (decryption logs)──► scm-decrypt-bypass ──► web GUI
                                              │
              bypass lists + terraform.tfvars │ Terraform (PaloAltoNetworks/scm)
                                              ▼
                                Strata Cloud Manager ──push──► firewall
```

Bypasses become ordinary SCM objects you can see and audit: a custom URL
category, address objects and **no-decrypt decryption rules** at the top of the
rulebase, scoped by the zones and source addresses you choose. A one-click
bypass is applied automatically only when the plan changes nothing but the
URL list; anything else stops and shows you the exact changes first.
See [How it works](docs/how-it-works.md).

## Quick start

You need Docker, an SCM service account, and an XML API key for the firewall.
[Prerequisites](docs/prerequisites.md) walks through creating them.

```bash
mkdir scm-decrypt-bypass && cd scm-decrypt-bypass
curl -fsSLO https://raw.githubusercontent.com/Former-Stranger/scm-decrypt-bypass/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/Former-Stranger/scm-decrypt-bypass/main/.env.example -o .env
$EDITOR .env                       # password, SCM service account, firewall
docker compose up -d               # creates ./data with starter files
$EDITOR data/terraform.tfvars      # set your SCM folder (required)
```

Open `http://<docker-host>:8088` and sign in. Before you rely on it, put it
behind HTTPS ([reverse proxy guide](docs/reverse-proxy.md)).

Just want a look? Demo mode needs no firewall or SCM account, and its deploys
are simulated:

```bash
docker run --rm -p 8088:8088 -e WEBGUI_DEMO=1 -e WEBGUI_AUTH=none ghcr.io/former-stranger/scm-decrypt-bypass
```

## Documentation

| Guide | |
|---|---|
| [Prerequisites](docs/prerequisites.md) | SCM service account, firewall API key, decryption logging |
| [Installation](docs/installation.md) | Docker Compose, upgrading, backups, running from source |
| [Configuration](docs/configuration.md) | Every environment variable, `terraform.tfvars` setting and bypass list |
| [Using it](docs/usage.md) | The web GUI and the command line |
| [How it works](docs/how-it-works.md) | Decryption exclusions vs. no-decrypt rules, matching rules, deploy safety |
| [HTTPS / reverse proxy](docs/reverse-proxy.md) | Caddy examples, including a private CA (step-ca) |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |

## Requirements and limits

- Firewalls managed by **Strata Cloud Manager**. The app talks to SCM for
  config and push, and to the firewall's management interface for logs.
- The Docker host must reach the firewall's management interface over HTTPS.
  Prisma Access, and firewalls whose logs are only in Strata Logging Service,
  aren't supported yet.
- Images are published for linux/amd64 and linux/arm64, on
  `ghcr.io/former-stranger/scm-decrypt-bypass` and `docker.io/formerstranger/scm-decrypt-bypass`.

## Security

The GUI can change your firewall's decryption policy, so it requires a
password by default, protects against cross-site requests, and runs as an
unprivileged user. Read [SECURITY.md](SECURITY.md) for the threat model and
how to report vulnerabilities.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License and disclaimer

[MIT](LICENSE). This project is not affiliated with, endorsed by or supported
by Palo Alto Networks. "Palo Alto Networks", "PAN-OS" and "Strata Cloud
Manager" are trademarks of their owners. It changes production firewall
configuration: review plans, test in a lab first, and use at your own risk.
