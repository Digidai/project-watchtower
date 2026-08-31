#!/usr/bin/python3
"""Repair consecutive failures with a cooldown; never restart on a single timeout."""
import json
from pathlib import Path
import subprocess
import socket
import ssl
import time
from equaldcdn_sync import probe, write_json, log


def tls_healthy():
    # Trust the explicitly installed self-signed server certificate, not arbitrary TLS.
    config = json.loads(Path("/etc/xray-trojan-ws/config.json").read_text())
    entry = next(i for i in config["inbounds"] if i.get("tag") == "trojan-ws-tls-in")
    cert = entry["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"]
    context = ssl.create_default_context(cafile=cert)
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="v2-oracle.syncany.app"):
                return True
    except (OSError, ssl.SSLError):
        return False


def main():
    path = Path("/var/lib/equaldcdn/watchdog.json")
    state = json.loads(path.read_text()) if path.exists() else {}
    expected = json.loads(Path("/etc/equaldcdn/subscription.json").read_text())["expected_ip"]
    for unit in ["xray-vless-global", "hysteria2-surge-test", "xray-trojan-ws"]:
        active = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
        if not active:
            subprocess.run(["systemctl", "start", unit], check=True, timeout=30)
            log("inactive_service_started", unit=unit)
    healthy = probe(7891, expected)
    state["tls_failures"] = 0 if tls_healthy() else state.get("tls_failures", 0) + 1
    if state["tls_failures"] >= 2 and time.time() - state.get("last_tls_recovery", 0) > 900:
        state["last_tls_recovery"] = time.time()
        write_json(path, state)
        subprocess.run(["systemctl", "restart", "xray-trojan-ws"], check=True, timeout=30)
        log("consecutive_tls_failures_restarted")
    state["failures"] = 0 if healthy else state.get("failures", 0) + 1
    if state["failures"] >= 2 and time.time() - state.get("last_recovery", 0) > 900:
        state["last_recovery"] = time.time()
        write_json(path, state)
        log("consecutive_exit_failures_sync_requested")
        subprocess.run(["systemctl", "start", "equaldcdn-sync.service"], check=True, timeout=240)
    write_json(path, state)


if __name__ == "__main__":
    main()
