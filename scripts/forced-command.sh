#!/usr/bin/env bash
set -Eeuo pipefail

ORIGINAL="${SSH_ORIGINAL_COMMAND:-core}"
case "$ORIGINAL" in
  core|self|github-lite|daily|weekly|venture-check|venture-discover)
    WATCHTOWER_BUSY_OK=1 WATCHTOWER_EXIT_ON_FAIL=1 exec /opt/project-watchtower/scripts/watchtower-run "$ORIGINAL"
    ;;
  status)
    exec /usr/bin/env sh -c 'test -f /var/lib/project-watchtower/reports/latest.json && cat /var/lib/project-watchtower/reports/latest.json || echo "{}"'
    ;;
  *)
    echo "command not allowed" >&2
    exit 126
    ;;
esac
