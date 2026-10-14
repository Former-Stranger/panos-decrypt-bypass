# HTTPS and reverse proxies

The app serves plain HTTP on port 8088. Since it can change your firewall's
decryption policy, put it behind HTTPS so the password and session cookie
aren't sent in clear text, and don't expose it to the internet.

Whatever proxy you use:

- pass the original `Host` header through (most proxies do by default); the
  app compares it with the browser's `Origin` to block cross-site requests;
- set `X-Forwarded-Proto: https`, or set `WEBGUI_COOKIE_SECURE=true`, so the
  session cookie is marked HTTPS-only;
- websockets aren't needed; the app uses plain HTTP requests.

## Caddy (ready-made example)

[`examples/caddy/`](../examples/caddy) runs the app and Caddy together. Caddy
gets and renews certificates by itself.

```bash
mkdir scm-decrypt-bypass && cd scm-decrypt-bypass
for f in compose.yaml Caddyfile Caddyfile.step-ca; do
  curl -fsSLO https://raw.githubusercontent.com/Former-Stranger/scm-decrypt-bypass/main/examples/caddy/$f
done
curl -fsSL https://raw.githubusercontent.com/Former-Stranger/scm-decrypt-bypass/main/.env.example -o .env
echo "SITE_ADDRESS=decrypt.example.com" >> .env   # your hostname
docker compose up -d
```

Pick the Caddyfile that matches how you get certificates:

| Caddyfile | Certificates from | Needs |
|---|---|---|
| `Caddyfile` with `tls internal` | Caddy's own CA | Nothing; trust Caddy's root in your browsers |
| `Caddyfile` without `tls internal` | Let's Encrypt | A public DNS name, ports 80/443 reachable from the internet for validation |
| `Caddyfile.step-ca` | Your own ACME CA, e.g. [step-ca](https://smallstep.com/docs/step-ca/) | An ACME provisioner, a DNS record the CA can resolve, port 80 reachable from the CA, and the CA's root mounted |

### Private CA with step-ca

`Caddyfile.step-ca` points Caddy's ACME client at your CA:

```caddyfile
{
	cert_issuer acme {
		dir https://ca.example.com:9000/acme/acme/directory
		trusted_roots /etc/caddy/root_ca.pem
	}
}

{$SITE_ADDRESS} {
	reverse_proxy scm-decrypt-bypass:8088
}
```

step-ca validates with the http-01 challenge, so it must reach Caddy on port 80
at the name you're requesting. step-ca's certificates last 24 hours by default;
Caddy renews them automatically, about a third of the lifetime before expiry.
`docker logs scm-decrypt-bypass-caddy | grep -i certificate` shows the
renewals.

## Adding it to an existing reverse proxy

If you already run a proxy on a Docker network, attach the app to that network
instead of publishing a port:

```yaml
services:
  scm-decrypt-bypass:
    # ...as in compose.yaml, but without "ports:"
    networks: [proxy]
networks:
  proxy:
    external: true   # your proxy's network
```

Then point the proxy at `scm-decrypt-bypass:8088`.

**Caddy:**

```caddyfile
decrypt.example.com {
	reverse_proxy scm-decrypt-bypass:8088
}
```

**nginx:**

```nginx
server {
    listen 443 ssl;
    server_name decrypt.example.com;
    ssl_certificate     /etc/nginx/certs/decrypt.crt;
    ssl_certificate_key /etc/nginx/certs/decrypt.key;

    location / {
        proxy_pass http://scm-decrypt-bypass:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

**Traefik** (labels on the app's service):

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.sdb.rule=Host(`decrypt.example.com`)
  - traefik.http.routers.sdb.tls=true
  - traefik.http.services.sdb.loadbalancer.server.port=8088
```

## Logging in through your proxy instead

If your proxy already authenticates users (for example with SSO via
oauth2-proxy or Authelia), you can turn off the app's own login with
`WEBGUI_AUTH=none`. Make sure the app's port is then reachable **only**
through the proxy: no `ports:` in its compose service.
