# Prerequisites

You need three things before installing: an SCM service account, an XML API
key for the firewall, and decryption logging on your decrypt rules. You also
need a Docker host that can reach both SCM and the firewall's management
interface.

## 1. Strata Cloud Manager service account

The app (and Terraform) use a service account to create the bypass objects and
push them.

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
interface through the PAN-OS XML API.

1. Create an **admin role profile** whose only permission is **XML API → Log**
   (turn off Web UI and the REST API). Configure it in SCM's device settings
   for the firewall, or locally on the firewall.
2. Create an administrator that uses that role.
3. Generate an API key for it. This prompts for the password so it isn't
   echoed or saved in your shell history (add `--cacert <ca.pem>` if the
   management certificate is from a private CA):

   ```bash
   read -rp "Admin: " U && read -rsp "Password: " P && echo && \
     curl -s https://firewall.example.com/api/ -d type=keygen \
       --data-urlencode "user=$U" --data-urlencode "password=$P"; unset P
   ```

4. Copy the value between `<key>` and `</key>` into `FIREWALL_API_KEY` in `.env`.

The key stops working if that admin's password changes.

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
| Firewall management interface | 443 | Reading decryption logs |
| `auth.apps.paloaltonetworks.com` | 443 | SCM authentication |
| `api.sase.paloaltonetworks.com` | 443 | SCM configuration and push |

**If the Docker host's own traffic is decrypted by the firewall**, the
container won't trust the forward-proxy certificate, and SCM calls fail with
`CERTIFICATE_VERIFY_FAILED`. Bypass decryption for those two hostnames (from the
Docker host at least) before you start.

## 5. The management certificate

The app verifies the firewall's management certificate. If it's issued by a
private CA, mount that CA's certificate into the container and set
`FIREWALL_CA_FILE` (see [Configuration](configuration.md)). The name in
`FIREWALL_HOST` must match the certificate.
