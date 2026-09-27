#!/usr/bin/env python3
"""PSCyber collector heartbeat: tell the SOC platform this collector is alive and
healthy. Runs every minute (systemd timer). Standard library only.

Sends nothing from the logs themselves - only service states, the Wazuh agent's
connection state, how many devices are sending syslog, and file sizes.
"""
import json
import os
import platform
import ssl
import subprocess
import urllib.request

ETC = "/etc/pscyber-collector"


def active(unit: str) -> str:
    try:
        return subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def agent_state() -> dict:
    out = {}
    try:
        for line in open("/var/ossec/var/run/wazuh-agentd.state"):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                out[k] = v.strip("'")
    except OSError:
        pass
    return {k: out.get(k) for k in ("status", "last_keepalive", "last_ack", "msg_count", "msg_sent")}


def main() -> None:
    cfg = json.load(open(f"{ETC}/config.json"))
    platform_url = cfg.get("platform_url") or open(f"{ETC}/platform_url").read().strip()
    sources = []
    try:
        for f in os.listdir("/var/log/pscyber/syslog"):
            p = f"/var/log/pscyber/syslog/{f}"
            sources.append({"device": f.removesuffix(".log"), "bytes": os.path.getsize(p)})
    except OSError:
        pass
    traps = os.path.getsize("/var/log/pscyber/snmptraps.log") if os.path.exists("/var/log/pscyber/snmptraps.log") else 0
    facts = {
        "services": {u: active(u) for u in ("pscyber-tunnel", "wazuh-agent", "rsyslog", "snmptrapd")},
        "wazuh_agent": agent_state(),
        "syslog_sources": sorted(sources, key=lambda s: -s["bytes"])[:50],
        "syslog_source_count": len(sources),
        "snmptrap_log_bytes": traps,
        "os": platform.platform(),
    }
    ctx = ssl.create_default_context(cafile=f"{ETC}/platform.pem") if os.path.exists(f"{ETC}/platform.pem") else ssl._create_unverified_context()
    req = urllib.request.Request(
        f"{platform_url}/api/collectors/heartbeat",
        data=json.dumps({"version": open("/opt/pscyber-collector/VERSION").read().strip(), "facts": facts}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {cfg['api_secret']}"}, method="POST")
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        reply = json.loads(r.read() or b"{}")
    # The SOC may change the site-agent enrolment password; keep ours current so
    # `pscyber-collector site-agent-command` always prints the working one.
    pw = reply.get("site_agent_enroll_password")
    if pw is not None and pw != cfg.get("site_agent_enroll_password"):
        cfg["site_agent_enroll_password"] = pw
        tmp = f"{ETC}/config.json.new"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(cfg, f, indent=1)
        os.replace(tmp, f"{ETC}/config.json")


if __name__ == "__main__":
    main()
