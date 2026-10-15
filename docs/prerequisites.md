# Prerequisites

First decide how the app changes your config. That depends on what manages
the firewall:

| The firewall is managed by | Set | Bypasses are |
|---|---|---|
| Strata Cloud Manager | `MANAGEMENT=scm` (default) | created in SCM and pushed |
| Nothing else: you configure it locally | `MANAGEMENT=local` | created on the firewall and committed |
| Panorama | | not supported |

You need an XML API key for the firewall and decryption logging on your
decrypt rules. With SCM you also need a service account. The Docker host must
reach the firewall's management interface (and SCM, if you use it).

## 1. Strata Cloud Manager service account (SCM only)

Skip this with `MANAGEMENT=local`. The app (and Terraform) use a service
account to create the bypass objects and push them.

1. In Strata Cloud Manager, go to **Settings → Identity & Access** and add an
   identity of type **Service Account**.
2. Save the **client ID** and **client secret** when they're shown; the secret
   isn't shown again.
3. Give it a role on the tenant that can edit configuration and push it.
   *Superuser* works. A narrower role works if it can manage NGFW
   configuration (decryption rules, URL categories, addresses, tags, EDLs,
   decryption profiles) and push config.
4. Note your **Tenant Service Group (TSG) ID**. It appears in SCM's tenant
   settings and inside the service account's client ID.

These go in `.env`:

```bash
SCM_CLIENT_ID=my-sa@1234567890.iam.panserviceaccount.com
SCM_CLIENT_SECRET=...
SCM_SCOPE=tsg_id:1234567890
```

Pushes made by the app only include **this service account's** changes, so
other admins' unfinished edits never go out with a bypass.

## 2. Firewall XML API key

The decryption log viewer reads logs straight from the firewall's management
interface through the PAN-OS XML API. With `MANAGEMENT=local` the same key
also creates the bypass objects and commits them.

1. Create an **admin role profile** with only the XML API permissions you
   need, and turn off the Web UI and the REST API:

   | Mode | XML API permissions |
   |---|---|
   | `scm` | **Log** |
   | `local` | **Log**, **Configuration**, **Operational Requests**, **Commit** |

   With SCM, configure the role in SCM's device settings for the firewall (or
   locally). With `local`, configure it on the firewall.
2. Create an administrator that uses that role. With `local`, put its name in
   `FIREWALL_USERNAME`: commits include only this admin's changes, so other
   admins' unfinished edits never go live with a bypass.
3. Generate an API key for it. This prompts for the password so it isn't
   echoed or saved in your shell history (add `--cacert <ca.pem>` if the
   management certificate is from a private CA):

   ```bash
   read -rp "Admin: " U && read -rsp "Password: " P && echo && \
     curl -s https://firewall.example.com/api/ -d type=keygen \
       --data-urlencode "user=$U" --data-urlencode "password=$P"; unset P
   ```

4. Copy the value between `<key>` and `</key>` into `FIREWALL_API_KEY` in `.env`.

The key stops working if that admin's password changes. With `local`, treat
the key like an admin password: it can change and commit the firewall's
config.

PAN-OS 11.x may add a warning to commit results that the key was generated
with a deprecated algorithm. It's harmless, but you can switch to the newer
keys under **Device → Setup → Management → Authentication Settings → API Key
Certificate**, then generate a new key.

## 3. Decryption logging

The viewer only sees what the firewall logs:

- **Failed handshakes:** your decryption policy rules need **Log Unsuccessful
  TLS Handshakes** (on by default). These are the failures the viewer shows.
- **Successful sessions** are optional. The no-decrypt rules this project
  creates log both, so you can see traffic your bypasses match (untick
  *Failures only* in the GUI).

The logs are read from the firewall itself, so no log forwarding is needed.

## 4. Network access from the Docker host

| From the Docker host to | Port | Used for |
|---|---|---|
| Firewall management interface | 443 | Reading decryption logs; with `local`, config and commits |
| `auth.apps.paloaltonetworks.com` | 443 | SCM authentication (SCM only) |
| `api.sase.paloaltonetworks.com` | 443 | SCM configuration and push (SCM only) |

**If the Docker host's own traffic is decrypted by the firewall**, the
container won't trust the forward-proxy certificate, and SCM calls fail with
`CERTIFICATE_VERIFY_FAILED`. Bypass decryption for those two hostnames (from the
Docker host at least) before you start.

## 5. The management certificate

The app verifies the firewall's management certificate. If it's issued by a
private CA, mount that CA's certificate into the container and set
`FIREWALL_CA_FILE` (see [Configuration](configuration.md)). The name in
`FIREWALL_HOST` must match the certificate. With `local`, Terraform trusts the
same CA.

A factory-default firewall uses a self-signed management certificate. Replace
it with one from your CA, or as a last resort, export the self-signed
certificate and use it as `FIREWALL_CA_FILE`.
