# Contributing

Thanks for helping! Bug reports, docs fixes and pull requests are all welcome.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and
[Terraform](https://developer.hashicorp.com/terraform/install) 1.9 or newer.

```bash
git clone https://github.com/Former-Stranger/scm-decrypt-bypass.git
cd scm-decrypt-bypass
uv sync
```

Run the GUI with sample data and simulated deploys (nothing is sent anywhere).
The password below is for this local demo only:

```bash
WEBGUI_DEMO=1 WEBGUI_PASSWORD=demo-password-1234 uv run scm-decrypt-bypass serve
```

Then open http://127.0.0.1:8088.

## Tests and checks

CI runs all of these on every pull request:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run python -m unittest discover tests
terraform -chdir=src/scm_decrypt_bypass/terraform init -backend=false
terraform -chdir=src/scm_decrypt_bypass/terraform test
docker build -t scm-decrypt-bypass:dev .
```

The Python tests use a fake `terraform` and a fake firewall, so they never
touch SCM or a real firewall. `terraform test` uses a mocked provider.

## Project layout

```
src/scm_decrypt_bypass/
  cli.py              command line and interactive menu
  bypass_lists.py     reading, validating and editing the bypass lists
  scm_api.py          SCM config push and job polling
  workspace.py        the data directory and Terraform working directory
  terraform/          the Terraform module (and its tests/)
  templates/          starter bypass lists and terraform.tfvars
  web/                FastAPI app, log poller, deployer, login, static page
tests/                Python tests and fixtures
docs/                 user documentation
```

## Pull requests

- Keep changes focused, and add or update tests for behaviour changes.
- Update the docs and `CHANGELOG.md` (under *Unreleased*) when users would notice.
- Never include real hostnames, IPs, tenant IDs, keys or logs from your network
  in code, tests or issues. Use `example.com` and `192.0.2.0/24`.

## Releasing (maintainers)

1. Move the *Unreleased* notes in `CHANGELOG.md` under the new version.
2. Bump `version` in `pyproject.toml` and run `uv lock`.
3. Commit, then tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The release workflow checks the tag matches `pyproject.toml`, publishes
multi-arch images and creates the GitHub Release from the changelog.
