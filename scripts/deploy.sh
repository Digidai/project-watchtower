#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

HOST="${WATCHTOWER_HOST:?set WATCHTOWER_HOST}"
USER="${WATCHTOWER_USER:-opc}"
KEY="${WATCHTOWER_KEY:?set WATCHTOWER_KEY}"
PORT="${WATCHTOWER_PORT:-22}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="$(mktemp -t project-watchtower.XXXXXX.tar.gz)"
AUTHORIZED_KEY_B64=""
DASHBOARD_PASSWORD_B64="${WATCHTOWER_DASHBOARD_PASSWORD_B64:-}"

if [ -n "${WATCHTOWER_AUTHORIZED_KEY:-}" ]; then
  AUTHORIZED_KEY_B64="$(printf '%s' "$WATCHTOWER_AUTHORIZED_KEY" | base64 | tr -d '\n')"
fi
if [ -z "$DASHBOARD_PASSWORD_B64" ] && [ -n "${WATCHTOWER_DASHBOARD_PASSWORD:-}" ]; then
  DASHBOARD_PASSWORD_B64="$(printf '%s' "$WATCHTOWER_DASHBOARD_PASSWORD" | base64 | tr -d '\n')"
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
  -o BatchMode=yes
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=2
  -o ConnectTimeout=20
)

scp_opts=(
  -i "$KEY"
  -P "$PORT"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o BatchMode=yes
  -o ConnectTimeout=20
)

remote_dir="$(ssh "${ssh_opts[@]}" "$USER@$HOST" 'mktemp -d /tmp/watchtower-deploy.XXXXXXXX')"
[[ "$remote_dir" =~ ^/tmp/watchtower-deploy\.[A-Za-z0-9]+$ ]] || exit 1
scp "${scp_opts[@]}" "$ARCHIVE" "$USER@$HOST:$remote_dir/code.tar.gz"

ssh "${ssh_opts[@]}" "$USER@$HOST" "WATCHTOWER_DEPLOY_DIR='$remote_dir' WATCHTOWER_AUTHORIZED_KEY_B64='$AUTHORIZED_KEY_B64' WATCHTOWER_DASHBOARD_PASSWORD_B64='$DASHBOARD_PASSWORD_B64' bash -s" <<'REMOTE'
set -Eeuo pipefail
umask 077
trap 'rm -rf -- "$WATCHTOWER_DEPLOY_DIR"' EXIT

command -v python3 >/dev/null
# Fail before changing the running dashboard if its private ingress is not ready.
sudo test -s /etc/project-watchtower/dashboard.env
sudo grep -q '^WATCHTOWER_ORIGIN_SECRET=.' /etc/project-watchtower/dashboard.env
systemctl is-active --quiet cloudflared-watchtower.service
curl -fsS --max-time 5 http://127.0.0.1:20241/ready >/dev/null

sudo mkdir -p /opt/project-watchtower /var/lib/project-watchtower/reports
sudo tar -xzf "$WATCHTOWER_DEPLOY_DIR/code.tar.gz" -C /opt/project-watchtower
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
  printf 'restrict,command="/opt/project-watchtower/scripts/forced-command.sh" %s\n' "$authorized_key" > "$tmp_authorized"
  sudo install -d -m 700 -o watchtower -g watchtower /var/lib/project-watchtower/.ssh
  sudo install -m 600 -o watchtower -g watchtower "$tmp_authorized" /var/lib/project-watchtower/.ssh/authorized_keys
  rm -f "$tmp_authorized"
fi

if [ -n "${WATCHTOWER_DASHBOARD_PASSWORD_B64:-}" ]; then
  tmp_dashboard_env="$(mktemp)"
  if sudo test -f /etc/project-watchtower/dashboard.env; then
    sudo sed '/^WATCHTOWER_DASHBOARD_PASSWORD/d' /etc/project-watchtower/dashboard.env > "$tmp_dashboard_env"
  fi
  printf 'WATCHTOWER_DASHBOARD_PASSWORD_B64=%s\n' "$WATCHTOWER_DASHBOARD_PASSWORD_B64" >> "$tmp_dashboard_env"
  sudo install -d -m 700 -o root -g root /etc/project-watchtower
  sudo install -m 600 -o root -g root "$tmp_dashboard_env" /etc/project-watchtower/dashboard.env
  rm -f "$tmp_dashboard_env"
fi

for unit in /opt/project-watchtower/systemd/project-watchtower-* /opt/project-watchtower/systemd/watchtower-proxy-status.service; do
  sudo install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
for unit in equaldcdn-sync xray-trojan-ws-watchdog cloudflared-watchtower; do
  sudo install -m 0644 "/opt/project-watchtower/ops/$unit.service" "/etc/systemd/system/$unit.service"
done
sudo install -d -m 0755 /etc/systemd/system/hysteria2-surge-test.service.d
sudo install -m 0644 /opt/project-watchtower/ops/hysteria-backend.conf /etc/systemd/system/hysteria2-surge-test.service.d/backend.conf
sudo install -m 0755 /opt/project-watchtower/ops/sync-equaldcdn-static-node.sh /usr/local/bin/sync-equaldcdn-static-node.sh
sudo install -m 0755 /opt/project-watchtower/ops/xray-trojan-ws-watchdog /usr/local/bin/xray-trojan-ws-watchdog
for obsolete in \
  project-watchtower-light.service \
  project-watchtower-light.timer \
  project-watchtower-venture.service \
  project-watchtower-venture.timer
do
  sudo systemctl disable --now "$obsolete" >/dev/null 2>&1 || true
  sudo rm -f "/etc/systemd/system/$obsolete"
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
if summary.get("status") not in {"ok", "warn"}:
    raise SystemExit(f"{mode} smoke failed: {summary}")
PY
}

smoke() {
  local mode="$1" output
  shift
  for _ in $(seq 1 10); do
    output="$(sudo -u watchtower env WATCHTOWER_BUSY_OK=1 "$@" /opt/project-watchtower/scripts/watchtower-run "$mode")"
    case "$output" in
      *'"status":"busy"'*|*'"status": "busy"'*) sleep 3 ;;
      *) require_nonfail_summary "$mode" "$output"; printf '%s\n' "$output"; return ;;
    esac
  done
  printf '%s smoke stayed busy; deployment not verified\n' "$mode" >&2
  return 1
}

smoke core WATCHTOWER_MAX_URLS=3 WATCHTOWER_MAX_BYTES=4194304
smoke venture-discover WATCHTOWER_MAX_URLS=2 WATCHTOWER_MAX_BYTES=12582912

sudo systemctl enable --now \
  project-watchtower-dashboard.service \
  project-watchtower-core.timer \
  project-watchtower-self.timer \
  project-watchtower-github-lite.timer \
  project-watchtower-daily.timer \
  project-watchtower-venture-check.timer \
  project-watchtower-venture-discover.timer
sudo systemctl restart project-watchtower-dashboard.service
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  sudo firewall-cmd --permanent --remove-service=http >/dev/null
  sudo firewall-cmd --permanent --remove-port=8765/tcp >/dev/null 2>&1 || true
  sudo firewall-cmd --reload >/dev/null
fi
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
smoke venture-check WATCHTOWER_MAX_URLS=5 WATCHTOWER_MAX_BYTES=12582912
sudo systemctl start watchtower-proxy-status.service
systemctl list-timers --all --no-pager 'project-watchtower-*'
REMOTE
