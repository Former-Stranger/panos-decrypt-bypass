# syntax=docker/dockerfile:1
# panos-decrypt-bypass: web GUI + CLI, with Terraform and the SCM and PAN-OS providers built in.
FROM python:3.14-slim

ARG TERRAFORM_VERSION=1.16.6
ARG TARGETARCH

# Terraform, verified against HashiCorp's published SHA256 sums.
RUN python - <<PY
import hashlib, io, urllib.request, zipfile
arch = "${TARGETARCH}" or "amd64"
base = "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}"
name = f"terraform_${TERRAFORM_VERSION}_linux_{arch}.zip"
sums = urllib.request.urlopen(f"{base}/terraform_${TERRAFORM_VERSION}_SHA256SUMS").read().decode()
want = next(line.split()[0] for line in sums.splitlines() if line.endswith(" " + name))
data = urllib.request.urlopen(f"{base}/{name}").read()
assert hashlib.sha256(data).hexdigest() == want, "terraform checksum mismatch"
zipfile.ZipFile(io.BytesIO(data)).extract("terraform", "/usr/local/bin")
PY
RUN chmod 755 /usr/local/bin/terraform && terraform version

COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

# Pre-install the SCM and PAN-OS providers into a local mirror and point
# Terraform at it, so `terraform init` never needs the registry at runtime.
RUN mkdir -p /opt/terraform/providers \
    && for module in scm local; do \
         cp -r /app/src/panos_decrypt_bypass/terraform/$module /tmp/tf-module \
         && (cd /tmp/tf-module && terraform init -backend=false -input=false -no-color > /dev/null \
             && terraform providers mirror -platform=linux_${TARGETARCH:-amd64} /opt/terraform/providers) \
         && rm -rf /tmp/tf-module || exit 1; \
       done \
    && rm -rf /tmp/.terraform.d \
    && printf '%s\n' \
       'provider_installation {' \
       '  filesystem_mirror {' \
       '    path    = "/opt/terraform/providers"' \
       '    include = ["registry.terraform.io/paloaltonetworks/*"]' \
       '  }' \
       '  direct {' \
       '    exclude = ["registry.terraform.io/paloaltonetworks/*"]' \
       '  }' \
       '}' > /opt/terraform/terraformrc

COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 755 /usr/local/bin/entrypoint && mkdir -p /data

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/tmp \
    DATA_DIR=/data \
    TF_CLI_CONFIG_FILE=/opt/terraform/terraformrc \
    WEBGUI_HOST=0.0.0.0 \
    WEBGUI_PORT=8088 \
    PUID=1000 \
    PGID=1000

VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('WEBGUI_PORT', '8088') + '/healthz', timeout=3)"]

ENTRYPOINT ["entrypoint"]
CMD ["panos-decrypt-bypass", "serve"]

LABEL org.opencontainers.image.title="panos-decrypt-bypass" \
      org.opencontainers.image.description="Find TLS decryption failures on Palo Alto Networks firewalls and bypass them in one click, through Strata Cloud Manager or on the firewall itself" \
      org.opencontainers.image.source="https://github.com/Former-Stranger/panos-decrypt-bypass" \
      org.opencontainers.image.licenses="MIT"
