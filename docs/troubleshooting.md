# Troubleshooting

Start with the status line at the top right of the GUI (last poll, or the
error), the deploy panel's **Log**, and the container log:

```bash
docker compose logs --tail 100 panos-decrypt-bypass
```

## The container keeps restarting

`docker compose logs` shows why. The usual causes:

| Message | Fix |
|---|---|
| `Set WEBGUI_PASSWORD (or WEBGUI_AUTH=none …)` | Add a password to `.env`. |
| `WEBGUI_PASSWORD must be at least 12 characters.` | Use a longer password. |
| `Permission denied` on `/data` | Set `PUID`/`PGID` in `.env` to the owner of `./data` (`id -u`, `id -g`). |

## The GUI shows no logs

| Status message | Fix |
|---|---|
| `FIREWALL_HOST, FIREWALL_API_KEY not set` | Fill them in `.env` and restart. |
| `Can't reach firewall … timed out` | The Docker host can't reach the management interface on 443: check routing, ACLs and the management interface's permitted IPs. |
| `CERTIFICATE_VERIFY_FAILED` | The management certificate isn't trusted. Mount its CA and set `FIREWALL_CA_FILE`. `FIREWALL_HOST` must match a name in the certificate. |
| `Firewall API error: Invalid Credential` | The API key is wrong, or the admin's password changed. Generate a new key. |
| No error, but nothing listed | There may simply be no failures. Untick *Failures only*, widen the window, and check that your decrypt rules log unsuccessful handshakes. |

**Times look shifted by a few hours:** set `FIREWALL_TIMEZONE` to the
firewall's timezone.

## Deploys fail

| Error | Fix |
|---|---|
| `Set folder (or snippet) in …/terraform.tfvars first` | Edit `data/terraform.tfvars`. |
| `Missing SCM_CLIENT_ID …` | Fill in the `SCM_*` values in `.env`. |
| `Refresh JWT Authentication error` / HTTP 401 | Wrong client ID, secret or `SCM_SCOPE` (`tsg_id:<id>`). |
| `CERTIFICATE_VERIFY_FAILED` contacting `api.sase.paloaltonetworks.com` or `auth.apps.paloaltonetworks.com` | Your firewall is decrypting the Docker host's own traffic to SCM. Bypass decryption for those hostnames (see [prerequisites](prerequisites.md#4-network-access-from-the-docker-host)). |
| `Object … already exists` / name conflict | An object with the same name already exists in SCM. Rename it, delete it, or import it into the state (below). |
| `Invalid Command … description is invalid` | Push descriptions are cleaned automatically; if you see this, please open an issue with the description. |
| A rule refers to an object that doesn't exist | Names in `source_addresses`, `no_decrypt_profile` and the EDL settings must exist in the folder or a parent folder. |

**The push failed but the apply worked:** the change is in SCM. Use
**Retry push** in the deploy panel, or `panos-decrypt-bypass push`. After a
restart, **Deploy…** finds nothing to apply and offers **Push to firewall**.

**A bypass is deployed but traffic is still decrypted:**

- Rules in parent folders are evaluated first: a decrypt rule above yours may
  match first. Move the bypass config to that folder, or adjust
  `rule_placement`.
- Check the zones and source in `terraform.tfvars` match the client.
- The firewall only sees the SNI. If the client sends a different name than
  you added (check the session details), add that name.

### Importing an existing object

```bash
docker compose exec panos-decrypt-bypass sh -c \
  'cd /data/terraform && terraform import "scm_decryption_exclusion.this[\"pinned.example.com\"]" "my-folder:::<uuid>"'
```

The ID format is `folder:::uuid` (or `:snippet::uuid`). Find the UUID in SCM or
through the SCM API.

## Hostnames ending in "…"

The firewall's decryption log keeps only the first 31 characters of the
hostname. Complete the name in the bypass dialog before adding it; the server
certificate's name shown in the dialog usually helps.

## Many unrelated sites fail with the same error

A single cause on the firewall is more likely than many broken sites: often the
decryption profile (TLS versions, ciphers, certificate checks) or the
forward-trust certificate. Bypassing them one by one hides the real problem.

## Getting help

Open an [issue](https://github.com/Former-Stranger/panos-decrypt-bypass/issues)
with the version, how you run it and the error. Remove hostnames, IPs, tenant
IDs and keys first.
