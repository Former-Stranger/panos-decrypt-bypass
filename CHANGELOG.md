# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
