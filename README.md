# panos-decrypt-bypass

[![CI](https://github.com/Former-Stranger/panos-decrypt-bypass/actions/workflows/ci.yml/badge.svg)](https://github.com/Former-Stranger/panos-decrypt-bypass/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Former-Stranger/panos-decrypt-bypass)](https://github.com/Former-Stranger/panos-decrypt-bypass/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Find TLS decryption failures on Palo Alto Networks firewalls, and bypass
them in one click.**

> [!IMPORTANT]
> **Works with firewalls managed by Strata Cloud Manager (SCM), or configured
> locally.** With SCM, bypasses are created in SCM and pushed; on a locally
> managed firewall they're created on the firewall and committed. Firewalls
> managed by Panorama aren't supported. Either way, the Docker host needs
> HTTPS access to the firewall's management interface.
>
> This project was called **scm-decrypt-bypass** until 0.2.0.
> See the [changelog](CHANGELOG.md#020) to upgrade.

SSL/TLS decryption breaks some apps: ones that pin their certificates, use
client certificates, or speak TLS the firewall can't proxy. Finding them
means digging through decryption logs, and fixing them means editing
decryption policy and pushing config. panos-decrypt-bypass does both:

- a **web GUI** that pulls decryption logs from the firewall, groups the
  failures by destination, explains each one in plain English, and helps you
  work out what an unfamiliar destination is (which clients use it, who
  registered it, its certificate, and commands that find the app on the
  client);
- a **Bypass…** button that adds the hostname to a no-decrypt URL category,
  applies it with Terraform, and pushes it from SCM or commits it on the
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
firewall ──XML API (decryption logs)──► panos-decrypt-bypass ──► web GUI
                                              │
              bypass lists + terraform.tfvars │ Terraform
                                              ▼
           MANAGEMENT=scm:   Strata Cloud Manager ──push──► firewalls
           MANAGEMENT=local: the firewall itself  ──commit
```

Bypasses become ordinary objects you can see and audit: a custom URL
category, address objects and **no-decrypt decryption rules** at the top of the
rulebase, scoped by the zones and source addresses you choose. A one-click
bypass is applied automatically only when the plan changes nothing but the
URL list; anything else stops and shows you the exact changes first.
See [How it works](docs/how-it-works.md).

## Quick start

You need Docker and an XML API key for the firewall, plus an SCM service
account if SCM manages the firewall.
[Prerequisites](docs/prerequisites.md) walks through creating them.

```bash
mkdir panos-decrypt-bypass && cd panos-decrypt-bypass
curl -fsSLO https://raw.githubusercontent.com/Former-Stranger/panos-decrypt-bypass/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/Former-Stranger/panos-decrypt-bypass/main/.env.example -o .env
$EDITOR .env                       # password, MANAGEMENT, firewall (+ SCM service account)
docker compose up -d               # creates ./data with starter files
$EDITOR data/terraform.tfvars      # SCM: set your folder (required); local: zones, vsys
```

Open `http://<docker-host>:8088` and sign in. Before you rely on it, put it
behind HTTPS ([reverse proxy guide](docs/reverse-proxy.md)).

Just want a look? Demo mode needs no firewall or SCM account, and its deploys
are simulated:

```bash
docker run --rm -p 8088:8088 -e WEBGUI_DEMO=1 -e WEBGUI_AUTH=none ghcr.io/former-stranger/panos-decrypt-bypass
```

## Documentation

| Guide | |
|---|---|
| [Prerequisites](docs/prerequisites.md) | Firewall API key, SCM service account, decryption logging |
| [Installation](docs/installation.md) | Docker Compose, upgrading, backups, running from source |
| [Configuration](docs/configuration.md) | Every environment variable, `terraform.tfvars` setting and bypass list |
| [Using it](docs/usage.md) | The web GUI and the command line |
| [How it works](docs/how-it-works.md) | Decryption exclusions vs. no-decrypt rules, matching rules, deploy safety |
| [HTTPS / reverse proxy](docs/reverse-proxy.md) | Caddy examples, including a private CA (step-ca) |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |

## Requirements and limits

- Firewalls managed by **Strata Cloud Manager** (`MANAGEMENT=scm`, the
  default), or a firewall **configured locally** (`MANAGEMENT=local`, tested
  with PAN-OS 11.2). One install manages one of these; run a second container for
  the other.
- Not supported: Panorama-managed firewalls, Prisma Access, and firewalls
  whose logs are only in Strata Logging Service.
- The Docker host must reach the firewall's management interface over HTTPS.
- Images are published for linux/amd64 and linux/arm64, on
  `ghcr.io/former-stranger/panos-decrypt-bypass` and `docker.io/formerstranger/panos-decrypt-bypass`.

## Security

The GUI can change your firewall's decryption policy, so it requires a
password by default, protects against cross-site requests, and runs as an
unprivileged user. Read [SECURITY.md](SECURITY.md) for the threat model and
how to report vulnerabilities.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License and disclaimer

[MIT](LICENSE). This project is not affiliated with, endorsed by or supported
by Palo Alto Networks. "Palo Alto Networks", "PAN-OS", "Panorama" and
"Strata Cloud Manager" are trademarks of their owners. It changes production firewall
configuration: review plans, test in a lab first, and use at your own risk.
