#!/usr/bin/python3
"""Root-only subscription sync. Keep a healthy residential path without churn."""
from __future__ import annotations

import copy
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.parse
import uuid

TAG = "exclusive-static-residential"
TARGET = Path("/etc/xray-vless-global/config.json")
STATE = Path("/var/lib/equaldcdn/state.json")
SECRET = Path("/etc/equaldcdn/subscription.json")
XRAY = "/usr/local/bin/xray"


def write_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".sync-")
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def log(event, **details):
    record = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "event": event, **details}
    print(json.dumps(record, ensure_ascii=False), flush=True)


def outbound(node):
    return {
        "tag": TAG, "protocol": "vless",
        "settings": {"vnext": [{"address": node["server"], "port": int(node["port"]),
            "users": [{"id": node["uuid"], "encryption": "none", "flow": node.get("flow", "")}]}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": node.get("servername", ""), "fingerprint": node.get("client-fingerprint", "chrome"),
            "publicKey": node["reality-opts"]["public-key"],
            "shortId": str(node["reality-opts"].get("short-id", "")), "spiderX": "/"}},
    }


def parse_nodes(document):
    import yaml
    data = yaml.safe_load(document)
    nodes = []
    for node in (data.get("proxies", []) if isinstance(data, dict) else []):
        if not isinstance(node, dict) or node.get("type") != "vless":
            continue
        if "\u4e13\u5c5e\u7eaf\u51c0\u9759\u6001\u4f4f\u5b85" not in str(node.get("name", "")):
            continue
        if not ipaddress.ip_address(node["server"]).is_global:
            raise ValueError("non-public residential server")
        if not 1 <= int(node["port"]) <= 65535:
            raise ValueError("invalid residential port")
        uuid.UUID(str(node["uuid"]))
        if not isinstance(node.get("reality-opts"), dict) or not node["reality-opts"].get("public-key"):
            raise ValueError("missing Reality parameters")
        nodes.append(node)
    if not nodes or len(nodes) > 8:
        raise ValueError("invalid residential candidate count")
    return nodes


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or target.hostname != "equaldcdn.com":
            raise ValueError("subscription redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "equaldcdn.com" or parsed.username:
        raise ValueError("subscription origin rejected")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SameHostRedirect())
    with opener.open(url, timeout=20) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError("subscription too large")
    return body.decode("utf-8")


def probe(port, expected_ip, attempts=2):
    # Either independent IP endpoint may establish a healthy, correct exit.
    for attempt in range(attempts):
        url = ("https://ipinfo.io/ip", "https://api.ipify.org")[attempt % 2]
        try:
            result = subprocess.run(["curl", "-4fsS", "--noproxy", "", "--socks5-hostname",
                f"127.0.0.1:{port}", "--connect-timeout", "4", "--max-time", "8", url],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip() == expected_ip:
                return True
        except subprocess.TimeoutExpired:
            pass
    return False


def choose(nodes, current, expected_ip, candidate_probe):
    current_out = next((o for o in current.get("outbounds", []) if o.get("tag") == TAG), None)
    matching = next((n for n in nodes if outbound(n) == current_out), None)
    if matching is not None and probe(7891, expected_ip):
        return matching, "healthy-current"
    # An updated credential on the same server takes priority over arbitrary ordering.
    address = ((current_out or {}).get("settings", {}).get("vnext") or [{}])[0].get("address")
    ordered = sorted(nodes, key=lambda n: (n["server"] != address, n["server"], int(n["port"])))
    for node in ordered:
        if candidate_probe(node):
            return node, "verified-failover"
    raise RuntimeError("no residential candidate passed exit verification")


def probe_candidate(node, expected_ip, directory):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
        "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}], "outbounds": [outbound(node)]}
    path = Path(directory) / "probe.json"
    write_json(path, config)
    proc = subprocess.Popen([XRAY, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            if proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.1)
        return probe(port, expected_ip)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def restart():
    subprocess.run(["systemctl", "restart", "xray-vless-global.service"], check=True, timeout=25)
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", 7891), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Xray listener did not become ready")


def main():
    os.umask(0o077)
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE.parent / "sync.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        settings = json.loads(SECRET.read_text())
        state = json.loads(STATE.read_text()) if STATE.exists() else {"switches": []}
        current = json.loads(TARGET.read_text())
        try:
            nodes = parse_nodes(fetch(settings["url"]))
            with tempfile.TemporaryDirectory(prefix="equaldcdn-", dir="/run/equaldcdn") as directory:
                selected, reason = choose(nodes, current, settings["expected_ip"],
                    lambda n: probe_candidate(n, settings["expected_ip"], directory))
                candidate = copy.deepcopy(current)
                candidate["outbounds"] = [outbound(selected), {"tag": "direct", "protocol": "freedom"},
                    {"tag": "block", "protocol": "blackhole"}]
                if candidate != current or reason == "verified-failover":
                    path = Path(directory) / "candidate.json"
                    write_json(path, candidate)
                    result = subprocess.run([XRAY, "run", "-test", "-c", str(path)],
                        capture_output=True, timeout=15)
                    if result.returncode:
                        raise RuntimeError("Xray configuration validation failed")
                    backup = STATE.parent / "backups" / f"config-{time.time_ns()}.json"
                    write_json(backup, current)
                    write_json(TARGET, candidate)
                    try:
                        restart()
                        if not probe(7891, settings["expected_ip"]):
                            raise RuntimeError("installed exit verification failed")
                    except Exception:
                        write_json(TARGET, current)
                        restart()
                        raise
                    state["switches"] = [t for t in state.get("switches", []) if t > time.time() - 7 * 86400]
                    if candidate != current:
                        state["switches"].append(time.time())
                    state["last_restart"] = time.time()
                    log("config_changed", server=selected["server"], reason=reason)
                    for old in sorted(backup.parent.glob("config-*.json"), reverse=True)[10:]:
                        old.unlink()
                else:
                    log("healthy_current_preserved", server=selected["server"])
                state.update(last_success=time.time(), last_error=None, server=selected["server"], reason=reason)
                write_json(STATE, state)
        except Exception as exc:
            state.update(last_attempt=time.time(), last_error=type(exc).__name__)
            write_json(STATE, state)
            log("sync_failed_config_preserved", error=type(exc).__name__)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
