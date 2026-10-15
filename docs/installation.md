# Installation

The recommended way to run panos-decrypt-bypass is the Docker image, which
includes Terraform and the SCM provider. Check the
[prerequisites](prerequisites.md) first.

## Docker Compose

```bash
mkdir panos-decrypt-bypass && cd panos-decrypt-bypass
curl -fsSLO https://raw.githubusercontent.com/Former-Stranger/panos-decrypt-bypass/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/Former-Stranger/panos-decrypt-bypass/main/.env.example -o .env
chmod 600 .env
```

1. **Edit `.env`.** At minimum set `WEBGUI_PASSWORD` (12+ characters), the
   three `SCM_*` values, `FIREWALL_HOST`, `FIREWALL_API_KEY` and
   `FIREWALL_TIMEZONE`. If your user's ID isn't 1000, set `PUID` and `PGID`
   to the output of `id -u` and `id -g`.
2. **Start it:**
   ```bash
   docker compose up -d
   ```
   The first start creates `./data` with starter files.
3. **Tell it where your config lives in SCM.** Edit `data/terraform.tfvars`
   and set `folder` (or `snippet`). Optionally narrow `from_zones`,
   `to_zones` and `source_addresses`, and attach a decryption profile. See
   [Configuration](configuration.md#terraformtfvars).
4. **Check the plan** (read-only):
   ```bash
   docker compose exec panos-decrypt-bypass panos-decrypt-bypass plan
   ```
   On a fresh install it shows the tag it will create, plus rules for any
   lists you've filled in.
5. **Open the GUI** at `http://<docker-host>:8088`. The first poll pulls the
   last 24 hours of decryption logs.

Then put it behind HTTPS: see the [reverse proxy guide](reverse-proxy.md).

### Images

| Registry | Image |
|---|---|
| GitHub Container Registry | `ghcr.io/former-stranger/panos-decrypt-bypass` |
| Docker Hub | `docker.io/formerstranger/panos-decrypt-bypass` |

Tags: `latest`, the exact version (`0.1.0`), and the minor line (`0.1`). Set
`PDB_VERSION` in `.env` to pin a version. Images are built for linux/amd64 and
linux/arm64, with provenance attestations and an SBOM.

### The data directory

Everything specific to your install lives in `./data` (mounted at `/data`):

```
data/
  terraform.tfvars     your settings
  bypass/*.txt         the bypass lists
  terraform/           Terraform working directory, including terraform.tfstate
  decrypt.db           decryption logs (kept RETENTION_DAYS)
  .session-key         signs login sessions
```

**Back it up**, especially `terraform/terraform.tfstate`: it's how Terraform
knows which SCM objects it manages. To keep state elsewhere, see
[remote state](configuration.md#remote-terraform-state).

### Running CLI commands

The CLI is in the image. Run it with `docker compose exec`:

```bash
docker compose exec panos-decrypt-bypass panos-decrypt-bypass list
docker compose exec panos-decrypt-bypass panos-decrypt-bypass add url example.org --subdomains -d "Vendor app"
docker compose exec panos-decrypt-bypass panos-decrypt-bypass   # interactive menu
```

An alias saves typing:

```bash
alias pdb='docker compose exec panos-decrypt-bypass panos-decrypt-bypass'
```

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Read the [changelog](../CHANGELOG.md) first. After an upgrade, click
**Deploy…** in the GUI (or run `plan`) to see whether the new version changes
anything in SCM.

## Running from source

For development, or without Docker. You need Python 3.12+,
[uv](https://docs.astral.sh/uv/) and Terraform 1.9+.

```bash
git clone https://github.com/Former-Stranger/panos-decrypt-bypass.git
cd panos-decrypt-bypass
uv sync
cp .env.example .env   # and fill it in
uv run panos-decrypt-bypass init
uv run panos-decrypt-bypass serve          # http://127.0.0.1:8088
```

The CLI reads `.env` from the current directory and keeps data in `./data`
(override with `DATA_DIR`). `serve` listens on 127.0.0.1 unless you pass
`--host` or set `WEBGUI_HOST`. Terraform downloads the SCM provider on first
use.

## Uninstalling

```bash
docker compose down
```

The bypass objects stay in SCM. To remove everything the app created first,
run `terraform destroy` in the data directory, then push:

```bash
docker compose exec panos-decrypt-bypass sh -c 'cd /data/terraform && terraform destroy'
docker compose exec panos-decrypt-bypass panos-decrypt-bypass push
```

Objects are named with the `name_prefix` (default `tf-ssl-bypass`) and tagged
with it, so they're easy to find in SCM.
