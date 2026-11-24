#!/bin/bash
# Startup script for a Google Compute Engine VM (Debian 12). It runs on every
# boot: installs Docker once, then (re)starts the server with the VM's current
# external IP as an sslip.io hostname, so HTTPS works without a domain.
#
# Settings come from instance metadata (see README):
#   lpd-image            container image, e.g. ghcr.io/OWNER/latency-proxy-detect:latest
#   lpd-admin-token      token for /admin.html
#   lpd-allowed-origins  e.g. https://OWNER.github.io
#   lpd-source-url       link to the source code shown on the page
set -euo pipefail

md() {
  curl -fs -H 'Metadata-Flavor: Google' \
    "http://metadata.google.internal/computeMetadata/v1/$1" || true
}

if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

IP=$(md instance/network-interfaces/0/access-configs/0/external-ip)
if [ -z "$IP" ]; then
  echo "no external IP" >&2
  exit 1
fi
DOMAIN="${IP//./-}.sslip.io"
IMAGE=$(md instance/attributes/lpd-image)
IMAGE=${IMAGE:-ghcr.io/OWNER/latency-proxy-detect:latest}

docker pull "$IMAGE"
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
