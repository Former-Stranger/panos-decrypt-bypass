# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.1] - 2026-10-27

### Changed
- **Find the app on the client:** the app search skips files over 1 GB (VM
  disk images and the like) and runs 8 searches at once on macOS and Linux.
  On a Mac with 63 GB to search it went from over 10 minutes to about 2.

## [0.4.0] - 2026-10-27

### Added
- **Find the app on the client**, under About this destination: ready-made
  macOS, Windows and Linux commands that search the client's installed apps
  for the destination's name, and show which process is connected to its IPs
  right now. Commands are only built from names and addresses that contain
  plainly safe characters.

## [0.3.0] - 2026-10-27

### Added
- **About this destination** in each expanded row: the clients that reached
  it, and an on-demand **Look up** with the domain's registration (RDAP), DNS
  (including the CDN behind it), the server's certificate, and links to
  VirusTotal, urlscan.io, crt.sh and a web search. Never contacts private
  addresses. `DOMAIN_LOOKUP=false` turns it off.
- Click any value in the details or the events table to copy it. Clicking a
  destination copies the IP without the port.

### Security
- TLS connections to the firewall's XML API and for lookups require TLS 1.2
  or later.

## [0.2.1] - 2026-10-25

### Fixed
- A push that the firewall rejects (SCM status `PUSHFAIL`) now fails straight
  away with the firewall's error lines. Before, the app kept waiting until
  its 30-minute timeout.

### Changed
- FastAPI 0.146.0 (from 0.143.1).

## [0.2.0] - 2026-10-15

### Added
- Support for locally managed firewalls (`MANAGEMENT=local`): a second
  Terraform module, using the PaloAltoNetworks/panos provider, creates the
  same URL category, address objects, tag, EDLs, profile and no-decrypt
  rules in a vsys on the firewall, and the app commits them over the XML
  API. Commits include only `FIREWALL_USERNAME`'s changes. One-click
  bypasses, review, retry and the CLI work as with SCM.
- `FIREWALL_CA_FILE` is also trusted by Terraform in local mode.
- `panos-decrypt-bypass commit` as an alias of `push`.
- `panos-decrypt-bypass terraform <args>` runs any Terraform command with the
  app's settings, for `destroy`, `import` and state commands.
- The status area now flags missing SCM or firewall settings for the
  selected mode.

### Changed
- **Renamed from scm-decrypt-bypass to panos-decrypt-bypass**: the
  repository, images (`ghcr.io/former-stranger/panos-decrypt-bypass`,
  `docker.io/formerstranger/panos-decrypt-bypass`), CLI command, Python
  package and compose service. `PDB_VERSION` replaces `SDB_VERSION`. See
  [upgrading from 0.1.0](docs/installation.md#upgrading-from-scm-decrypt-bypass-010).
- The bypass tag's comment now names panos-decrypt-bypass, so the first
  deploy after upgrading shows it as a change to review.
- Signing in again is needed once, because the session cookie was renamed.
- The SCM Terraform module moved to `terraform/scm/`. Data directories are
  migrated automatically, and module files from older versions are removed.

### Notes
- Decryption exclusions (`exclusion-hostnames.txt`) remain SCM-only. On a
  locally managed firewall they're ignored with a warning.

## [0.1.0] - 2026-10-14

First public release.

### Added
- Web GUI that polls the firewall's XML API for decryption logs, groups
  failures by destination, explains each error, and shows which bypass
  entries already cover it.
- One-click bypass: adds hostnames to the no-decrypt URL category, plans,
  applies and pushes to the firewall, stopping for review when the plan
  changes anything else.
- Built-in password login with signed session cookies, cross-site request
  protection and security headers.
- CLI (`scm-decrypt-bypass`) with an interactive menu and add / remove /
  list / plan / deploy / push / init / serve commands.
- Terraform module (PaloAltoNetworks/scm provider) for custom decryption
  exclusions and ordered no-decrypt rules matching URL lists, URL
  categories, addresses, users and EDLs.
- Docker image with Terraform and the SCM provider pre-installed, for
  linux/amd64 and linux/arm64.
- Demo mode with sample logs and simulated deploys.
