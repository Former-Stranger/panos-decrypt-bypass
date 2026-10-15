# Security policy

panos-decrypt-bypass changes the decryption policy of production firewalls, so
security reports are taken seriously.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private vulnerability
reporting instead: the **Security** tab of this repository → **Report a
vulnerability**. You'll get an acknowledgement within a week.

Only the latest release is supported with fixes.

## Threat model

What the app protects, and how:

| Concern | How it's handled |
|---|---|
| **Who can change the firewall** | The web GUI requires a password (`WEBGUI_PASSWORD`, at least 12 characters) unless explicitly disabled with `WEBGUI_AUTH=none`. Sessions are signed, HttpOnly, `SameSite=Strict` cookies, and repeated failed logins are throttled. |
| **Cross-site requests** | Every request that changes something needs a custom header and a same-origin `Origin`, which another website can't send. Pages are served with a strict Content-Security-Policy, `X-Frame-Options: DENY` and `nosniff`. |
| **Hostile log content** | SNI, certificate names and error strings in decryption logs are controlled by whoever is on either end of the connection. The page only inserts them as text, never as HTML. Hostnames are validated before they reach a bypass list or Terraform. |
| **Scope of a bypass** | One-click bypasses only add hostnames to the no-decrypt URL category, whose rule is scoped by the zones and source addresses you configure. A deploy applies without review only if the plan changes nothing but that list. |
| **Credentials** | SCM and firewall credentials are read from the environment (`.env`), never stored by the app or written to logs. TLS to the firewall is verified by default. |
| **Container** | The app runs as an unprivileged user (`PUID`/`PGID`). Terraform is checksum-verified at build time, and the SCM provider is pre-installed, so no providers are downloaded at runtime. Release images carry provenance attestations and an SBOM. |

## Recommended deployment

- Put the GUI behind HTTPS (see [docs/reverse-proxy.md](docs/reverse-proxy.md)),
  and don't expose it to the internet.
- Give the SCM service account and the firewall API admin only the access they
  need (see [docs/prerequisites.md](docs/prerequisites.md)).
- Back up the data directory: it holds your Terraform state.
