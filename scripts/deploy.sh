#!/usr/bin/env bash
set -Eeuo pipefail

HOST="${WATCHTOWER_HOST:?set WATCHTOWER_HOST}"
USER="${WATCHTOWER_USER:-opc}"
KEY="${WATCHTOWER_KEY:?set WATCHTOWER_KEY}"
PORT="${WATCHTOWER_PORT:-22}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="$(mktemp -t project-watchtower.XXXXXX.tar.gz)"
AUTHORIZED_KEY_B64=""

if [ -n "${WATCHTOWER_AUTHORIZED_KEY:-}" ]; then
  AUTHORIZED_KEY_B64="$(printf '%s' "$WATCHTOWER_AUTHORIZED_KEY" | base64 | tr -d '\n')"
fi

cleanup() {
  rm -f "$ARCHIVE"
}
trap cleanup EXIT

tar \
  --exclude='.git' \
  --exclude='reports' \
  --exclude='*.pyc' \
  -czf "$ARCHIVE" \
  -C "$ROOT" .

ssh_opts=(
  -i "$KEY"
  -p "$PORT"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=20
)

scp "${ssh_opts[@]}" "$ARCHIVE" "$USER@$HOST:/tmp/project-watchtower.tar.gz"

ssh "${ssh_opts[@]}" "$USER@$HOST" "WATCHTOWER_AUTHORIZED_KEY_B64='$AUTHORIZED_KEY_B64' bash -s" <<'REMOTE'
set -Eeuo pipefail

command -v python3 >/dev/null

sudo mkdir -p /opt/project-watchtower /var/lib/project-watchtower/reports
sudo tar -xzf /tmp/project-watchtower.tar.gz -C /opt/project-watchtower
sudo chmod +x /opt/project-watchtower/scripts/watchtower-run /opt/project-watchtower/scripts/forced-command.sh

if ! id watchtower >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/project-watchtower --shell /bin/bash watchtower
else
  sudo usermod --home /var/lib/project-watchtower --shell /bin/bash watchtower
fi

sudo chown -R root:root /opt/project-watchtower
sudo chown -R watchtower:watchtower /var/lib/project-watchtower

if [ -n "${WATCHTOWER_AUTHORIZED_KEY_B64:-}" ]; then
  authorized_key="$(printf '%s' "$WATCHTOWER_AUTHORIZED_KEY_B64" | base64 -d)"
  tmp_authorized="$(mktemp)"
  printf 'command="/opt/project-watchtower/scripts/forced-command.sh",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc %s\n' "$authorized_key" > "$tmp_authorized"
  sudo install -d -m 700 -o watchtower -g watchtower /var/lib/project-watchtower/.ssh
  sudo install -m 600 -o watchtower -g watchtower "$tmp_authorized" /var/lib/project-watchtower/.ssh/authorized_keys
  rm -f "$tmp_authorized"
fi

sudo install -m 0644 /opt/project-watchtower/systemd/project-watchtower-light.service /etc/systemd/system/project-watchtower-light.service
sudo install -m 0644 /opt/project-watchtower/systemd/project-watchtower-light.timer /etc/systemd/system/project-watchtower-light.timer
sudo install -m 0644 /opt/project-watchtower/systemd/project-watchtower-daily.service /etc/systemd/system/project-watchtower-daily.service
sudo install -m 0644 /opt/project-watchtower/systemd/project-watchtower-daily.timer /etc/systemd/system/project-watchtower-daily.timer
sudo systemctl daemon-reload
sudo systemctl enable --now project-watchtower-light.timer project-watchtower-daily.timer

sudo -u watchtower /opt/project-watchtower/scripts/watchtower-run light
REMOTE
