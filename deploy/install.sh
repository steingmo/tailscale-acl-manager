#!/bin/bash
# Builds tailscale-acl from this source folder and installs it as a systemd
# service. Run as root on the server (Ubuntu or Debian with Swift installed);
# run again to update. See docs/web-service.md.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

echo "Building (the first build takes several minutes)…"
# Swift's own libraries linked in, so the binary doesn't depend on the toolchain.
swift build -c release --static-swift-stdlib -j "${JOBS:-2}" --product TailscaleACL
bin="$(swift build -c release --static-swift-stdlib --show-bin-path)/TailscaleACL"
install -m 0755 "$bin" /usr/local/bin/tailscale-acl.new
mv /usr/local/bin/tailscale-acl.new /usr/local/bin/tailscale-acl

# Its own account, no shell, no home of its own.
id tailscale-acl >/dev/null 2>&1 || useradd --system --user-group --no-create-home \
  --home-dir /var/lib/tailscale-acl --shell /usr/sbin/nologin tailscale-acl
# Config and secrets: written by root, readable by the service, by nobody else.
install -d -m 0750 -o root -g tailscale-acl /etc/tailscale-acl
install -m 0640 -o root -g tailscale-acl deploy/server.json.example /etc/tailscale-acl/server.json.example

install -m 0755 deploy/tailscale-acl-user /usr/local/sbin/tailscale-acl-user
install -m 0644 deploy/tailscale-acl.service /etc/systemd/system/tailscale-acl.service
install -m 0644 deploy/logrotate /etc/logrotate.d/tailscale-acl
systemctl daemon-reload

if [ -e /etc/tailscale-acl/server.json ]; then
  systemctl enable --quiet tailscale-acl
  systemctl restart tailscale-acl
  sleep 2
  systemctl --no-pager --lines=5 status tailscale-acl || true
else
  cat <<NEXT

Installed. Next:
  1. Write /etc/tailscale-acl/server.json (start from server.json.example) and the
     secret files it names, each holding only the secret:
       install -m 0640 -o root -g tailscale-acl /dev/null /etc/tailscale-acl/entra-secret
  2. tailscale-acl serve --config /etc/tailscale-acl/server.json --check
  3. systemctl enable --now tailscale-acl
NEXT
fi
