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

COPYFILE_DISABLE=1 tar --format ustar \
  --exclude='.git' \
  --exclude='.secrets' \
  --exclude='__pycache__' \
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

scp_opts=(
  -i "$KEY"
  -P "$PORT"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=20
)

scp "${scp_opts[@]}" "$ARCHIVE" "$USER@$HOST:/tmp/project-watchtower.tar.gz"

ssh "${ssh_opts[@]}" "$USER@$HOST" "WATCHTOWER_AUTHORIZED_KEY_B64='$AUTHORIZED_KEY_B64' bash -s" <<'REMOTE'
set -Eeuo pipefail

command -v python3 >/dev/null

sudo mkdir -p /opt/project-watchtower /var/lib/project-watchtower/reports
sudo tar -xzf /tmp/project-watchtower.tar.gz -C /opt/project-watchtower
sudo rm -rf /opt/project-watchtower/.secrets /opt/project-watchtower/reports /opt/project-watchtower/watchtower/__pycache__
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

for unit in /opt/project-watchtower/systemd/project-watchtower-*; do
  sudo install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
sudo systemctl daemon-reload

if ! pgrep -u watchtower -f 'watchtower.cli run' >/dev/null 2>&1; then
  sudo rm -rf /tmp/project-watchtower.lock /var/lib/project-watchtower/project-watchtower.lock
fi

require_nonfail_summary() {
  local mode="$1"
  local output="$2"
  SMOKE_MODE="$mode" SMOKE_OUTPUT="$output" python3 - <<'PY'
import json
import os
import sys

mode = os.environ["SMOKE_MODE"]
try:
    payload = json.loads(os.environ["SMOKE_OUTPUT"])
except Exception as exc:
    raise SystemExit(f"{mode} smoke did not return JSON: {exc}")
summary = payload.get("summary")
if not isinstance(summary, dict):
    raise SystemExit(f"{mode} smoke did not return a summary")
if summary.get("status") == "fail":
    raise SystemExit(f"{mode} smoke failed: {summary}")
PY
}

sudo -u watchtower env WATCHTOWER_BUSY_OK=1 WATCHTOWER_MAX_URLS=3 WATCHTOWER_MAX_BYTES=4194304 /opt/project-watchtower/scripts/watchtower-run core
sudo -u watchtower env WATCHTOWER_BUSY_OK=1 WATCHTOWER_MAX_URLS=2 WATCHTOWER_MAX_BYTES=12582912 /opt/project-watchtower/scripts/watchtower-run venture-discover

sudo systemctl disable --now project-watchtower-venture.timer >/dev/null 2>&1 || true
sudo systemctl enable --now \
  project-watchtower-core.timer \
  project-watchtower-self.timer \
  project-watchtower-light.timer \
  project-watchtower-github-lite.timer \
  project-watchtower-daily.timer \
  project-watchtower-venture-check.timer \
  project-watchtower-venture-discover.timer
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! pgrep -u watchtower -f 'watchtower.cli run' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
if ! pgrep -u watchtower -f 'watchtower.cli run' >/dev/null 2>&1; then
  sudo rm -rf /tmp/project-watchtower.lock /var/lib/project-watchtower/project-watchtower.lock
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
  self_smoke="$(sudo -u watchtower env WATCHTOWER_BUSY_OK=1 /opt/project-watchtower/scripts/watchtower-run self)"
  printf '%s\n' "$self_smoke"
  case "$self_smoke" in
    *'"status":"busy"'*|*'"status": "busy"'*) sleep 2 ;;
    *) break ;;
  esac
done
require_nonfail_summary self "$self_smoke"
sudo -u watchtower env WATCHTOWER_BUSY_OK=1 WATCHTOWER_MAX_URLS=5 WATCHTOWER_MAX_BYTES=12582912 /opt/project-watchtower/scripts/watchtower-run venture-check
systemctl list-timers --all --no-pager 'project-watchtower-*'
REMOTE
