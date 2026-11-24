#!/bin/bash
# Startup script for a Google Compute Engine VM (Debian 12). It runs on every
# boot: installs Docker once, then (re)starts the server with the VM's current
# external IP as an sslip.io hostname, so HTTPS works without a domain.
#
# Settings come from instance metadata (see README):
#   lpd-repo             git URL to build from, e.g. https://github.com/OWNER/latency-proxy-detect
#   lpd-image            or: a ready container image, e.g. ghcr.io/OWNER/latency-proxy-detect:latest
#   lpd-admin-token      token for /admin.html
#   lpd-allowed-origins  e.g. https://OWNER.github.io
#   lpd-source-url       link to the source code shown on the page
set -euo pipefail

md() {
  curl -fs -H 'Metadata-Flavor: Google' \
    "http://metadata.google.internal/computeMetadata/v1/$1" || true
}

if ! command -v docker >/dev/null || ! command -v git >/dev/null; then
  apt-get update
  apt-get install -y docker.io git
  systemctl enable --now docker
fi

# An e2-micro has 1 GB of memory; swap keeps the Go build from running out.
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
swapon /swapfile 2>/dev/null || true

IP=$(md instance/network-interfaces/0/access-configs/0/external-ip)
if [ -z "$IP" ]; then
  echo "no external IP" >&2
  exit 1
fi
DOMAIN="${IP//./-}.sslip.io"
IMAGE=$(md instance/attributes/lpd-image)
REPO=$(md instance/attributes/lpd-repo)
if [ -n "$IMAGE" ]; then
  docker pull "$IMAGE"
elif [ -n "$REPO" ]; then
  # Build from source: no registry needed.
  rm -rf /opt/lpd-src
  git clone --depth 1 "$REPO" /opt/lpd-src
  docker build -t latency-proxy-detect:local /opt/lpd-src
  IMAGE=latency-proxy-detect:local
else
  echo "set the lpd-repo or lpd-image metadata" >&2
  exit 1
fi
docker rm -f lpd >/dev/null 2>&1 || true
# --network host: visitors must connect straight to the server process, with
# nothing in between, or the measurement is meaningless.
docker run -d --name lpd --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /var/lib/lpd:/data \
  -e LPD_DOMAIN="$DOMAIN" \
  -e LPD_ADMIN_TOKEN="$(md instance/attributes/lpd-admin-token)" \
  -e LPD_ALLOWED_ORIGINS="$(md instance/attributes/lpd-allowed-origins)" \
  -e LPD_SOURCE_URL="$(md instance/attributes/lpd-source-url)" \
  "$IMAGE"

echo "latency-proxy-detect is starting at https://$DOMAIN"
