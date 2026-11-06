# lockssh in Docker: the separated setup baked into an image. The console
# runs as "lockssh" in one container and holds the SSH key in its home
# volume; the agent's MCP server runs as "agent" in another; they share the
# socket directory through a named volume, and the kernel checks every peer
# as it does on a host.
# See docs/docker.md.
#
#   docker build -t lockssh .
#   docker build --target vault -t lockssh .   # with the vault CLI, for credentials = "vault"
#
# The base images are pinned by digest: update the tag and the digest
# together (docker buildx imagetools inspect golang:1.26-alpine).

FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/lockssh ./cmd/lockssh

# The HashiCorp Vault CLI, checked against the sums pinned here (update them
# with VAULT_VERSION from releases.hashicorp.com/vault/<version>/).
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS vault-cli
ARG TARGETARCH
ARG VAULT_VERSION=2.2.0
ARG VAULT_SHA256_amd64=05d78b0ac842ca7c522fc297df91527cd43c15420c4c5c0a969d48a7b0ff7b6d
ARG VAULT_SHA256_arm64=9d9ae0ce520744fb095bdf150a6924f5583528fd385a2e92782f7a6d00cad53c
RUN set -eu; arch=${TARGETARCH:-amd64}; \
    case $arch in amd64) sum=$VAULT_SHA256_amd64 ;; arm64) sum=$VAULT_SHA256_arm64 ;; *) echo "no vault CLI for $arch" >&2; exit 1 ;; esac; \
    wget -qO /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${arch}.zip"; \
    echo "$sum  /tmp/vault.zip" | sha256sum -c -; \
    unzip -q /tmp/vault.zip vault -d /out

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS console
# ALLOWED_UIDS: comma-separated uids that may reach the console besides the
# members of lockssh-clients, for an agent in a container of its own whose
# uid has no account here (docs/docker.md#agent-in-its-own-container).
# Never root (0) nor the console's own uid (10041).
ARG ALLOWED_UIDS=""
# The ids differ from the other locks' images (locksql 10000-10002, lockmq
# 10010-10012, lockhttp 10020-10022, lockfile 10030-10032, locklog
# 10050-10052), so that one agent image can hold the client setup of all.
# ca-certificates: the vault CLI's https.
RUN case "$ALLOWED_UIDS" in *[!0-9,]*|,*|*,|*,,*) echo "ALLOWED_UIDS: want comma-separated decimal uids" >&2; exit 1;; esac \
 && for u in $(echo "$ALLOWED_UIDS" | tr ',' ' '); do \
      case "$u" in 0*|10041|65534) echo "ALLOWED_UIDS: $u is root, the console account, nobody (or has a leading zero)" >&2; exit 1;; esac; \
    done \
 && apk add --no-cache ca-certificates \
 && addgroup -S -g 10040 lockssh-clients \
 && adduser -D -u 10041 -s /bin/sh -g "lockssh console" lockssh \
 && adduser -D -u 10042 -G lockssh-clients -s /bin/sh -g "lockssh agent" agent \
 && chmod 0700 /home/lockssh \
 && install -d -m 0755 -o root -g root /etc/lockssh \
 && printf '%s\n' \
      '# lockssh: the console runs as service_user; members of client_group reach it.' \
      'service_user = "lockssh"' \
      'client_group = "lockssh-clients"' \
      'socket_dir   = "/run/lockssh"' \
      'x11          = "refuse"' > /etc/lockssh/system.toml \
 && if [ -n "$ALLOWED_UIDS" ]; then printf 'allowed_uids = [%s]\n' "$ALLOWED_UIDS" >> /etc/lockssh/system.toml; fi \
 && chmod 0644 /etc/lockssh/system.toml \
 && install -d -m 2710 -o lockssh -g lockssh-clients /run/lockssh
COPY --from=build --chown=root:root --chmod=0755 /out/lockssh /usr/local/bin/lockssh

# Named volumes take these directories' owner and mode on first use.
VOLUME ["/run/lockssh", "/home/lockssh"]
WORKDIR /
USER agent
ENTRYPOINT ["lockssh"]
CMD ["help"]

# The console with the vault CLI (docs/docker.md, Credentials from Vault).
# Not the default: the CLI adds some 550 MB.
FROM console AS vault
COPY --from=vault-cli --chown=root:root --chmod=0755 /out/vault /usr/local/bin/vault

# The default image.
FROM console
