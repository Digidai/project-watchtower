#!/usr/bin/python3
"""Publish allowlisted proxy configuration fields, never authentication data."""
import json
import os
from pathlib import Path
import tempfile
import time

DEST = Path("/run/project-watchtower-status")


def sanitize(config):
    result = {"log": {"loglevel": config.get("log", {}).get("loglevel")}, "inbounds": [], "outbounds": []}
    for inbound in config.get("inbounds", []):
        item = {k: inbound[k] for k in ("tag", "protocol", "listen", "port") if k in inbound}
        stream = inbound.get("streamSettings", {})
        item["streamSettings"] = {k: stream[k] for k in ("network", "security") if k in stream}
        item["streamSettings"]["wsSettings"] = {k: stream.get("wsSettings", {}).get(k) for k in ("path", "heartbeatPeriod")}
        item["streamSettings"]["tlsSettings"] = {"certificates": [
            {"certificateFile": c.get("certificateFile", "")} for c in stream.get("tlsSettings", {}).get("certificates", [])]}
        result["inbounds"].append(item)
    for outbound in config.get("outbounds", []):
        item = {k: outbound[k] for k in ("tag", "protocol") if k in outbound}
        item["settings"] = {key: [{k: n.get(k) for k in ("address", "port")} for n in outbound.get("settings", {}).get(key, [])]
                            for key in ("vnext", "servers")}
        # Preserve the existence of a forbidden routing option for the self-check.
        if "dialerProxy" in json.dumps(outbound):
            item["dialerProxy"] = "present"
        result["outbounds"].append(item)
    return result


def publish(name, value):
    fd, temp = tempfile.mkstemp(dir=DEST)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o644)
            json.dump(value, stream)
        os.replace(temp, DEST / name)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    DEST.mkdir(mode=0o755, exist_ok=True)
    for name, path in [("xray.json", "/etc/xray-vless-global/config.json"),
                       ("trojan.json", "/etc/xray-trojan-ws/config.json")]:
        publish(name, sanitize(json.loads(Path(path).read_text())))
    state_path = Path("/var/lib/equaldcdn/state.json")
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    publish("health.json", {"generated_at": time.time(), "last_success": state.get("last_success"),
        "last_error": state.get("last_error"), "reason": state.get("reason"),
        "switches_24h": sum(t > time.time() - 86400 for t in state.get("switches", [])),
        "credentials_private": not (Path("/etc/xray-vless-global/config.json").stat().st_mode & 0o077)})


if __name__ == "__main__":
    main()
