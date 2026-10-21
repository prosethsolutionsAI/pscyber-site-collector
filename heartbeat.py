#!/usr/bin/env python3
"""PSCyber collector heartbeat: tell the SOC platform this collector is alive and
healthy. Runs every minute (systemd timer). Standard library only.

Sends nothing from the logs themselves - only service states, the Wazuh agent's
connection state, how many devices are sending syslog, file sizes, and (1.2.2+) the
box's own CPU, load, memory and disk use.
"""
import json
import os
import platform
import ssl
import subprocess
import time
import urllib.error
import urllib.request

ETC = "/etc/pscyber-collector"


def active(unit: str) -> str:
    try:
        return subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _importable(module: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(module) is not None


def ansible_version() -> str:
    """'2.19.4' when ansible-playbook and sshpass are both here, else '' (cannot run playbooks)."""
    import shutil
    if not (shutil.which("ansible-playbook") and shutil.which("sshpass")):
        return ""
    try:
        first = subprocess.run(["ansible-playbook", "--version"], capture_output=True, text=True, timeout=20).stdout.splitlines()[0]
        return first.split("[core")[-1].strip(" ]") if "[core" in first else first.split()[-1]
    except Exception:  # noqa: BLE001
        return ""


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


REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "ntfs", "f2fs", "jfs", "reiserfs"}


def system(proc: str = "/proc", mounts: str = "/proc/mounts") -> dict:
    """The box's own CPU, load, memory and disk use - numbers only. The platform shows them on
    the Site collectors page and warns before a disk fills (1.2.2+)."""
    out: dict = {}
    try:
        def stat():
            v = [int(x) for x in open(f"{proc}/stat").readline().split()[1:9]]
            return sum(v), v[3] + v[4]
        t1, i1 = stat()
        time.sleep(1)
        t2, i2 = stat()
        if t2 > t1:
            out["cpu_pct"] = round(100.0 * ((t2 - t1) - (i2 - i1)) / (t2 - t1), 1)
        out["load"] = [float(x) for x in open(f"{proc}/loadavg").read().split()[:3]]
        out["cores"] = os.cpu_count()
        mem = {line.split(":")[0]: int(line.split()[1]) for line in open(f"{proc}/meminfo") if len(line.split()) > 1}
        out["mem_total_kb"], out["mem_avail_kb"] = mem.get("MemTotal"), mem.get("MemAvailable")
        out["uptime_s"] = int(float(open(f"{proc}/uptime").read().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    disks, seen = [], set()
    try:
        for line in open(mounts):
            dev, mnt, fstype = line.split()[:3]
            if fstype not in REAL_FS or dev in seen:
                continue
            seen.add(dev)  # one line per device: bind mounts repeat it
            mnt = mnt.replace("\\040", " ")
            try:
                st = os.statvfs(mnt)
            except (OSError, AttributeError):
                continue
            size = st.f_blocks * st.f_frsize // 1024
            used = (st.f_blocks - st.f_bfree) * st.f_frsize // 1024
            if size:
                disks.append({"mount": mnt, "size_kb": size, "used_kb": used,
                              "pct": round(100.0 * used / (used + st.f_bavail * st.f_frsize // 1024 or 1), 1)})
    except OSError:
        pass
    out["disks"] = disks[:15]
    return out


def feeds() -> dict:
    """1.2.3+: is the cloud-feed file read by the Wazuh agent, and how big is each feed file."""
    try:
        localfile = "PSCYBER-FEEDS" in open("/var/ossec/etc/ossec.conf").read()
    except OSError:
        localfile = False
    files = {}
    try:
        for f in os.listdir("/var/log/pscyber/feeds"):
            if f.endswith(".json"):
                files[f[:-5]] = os.path.getsize(f"/var/log/pscyber/feeds/{f}")
    except OSError:
        pass
    return {"localfile": localfile, "files": files}


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
        "services": {u: active(u) for u in ("pscyber-tunnel", "wazuh-agent", "rsyslog", "snmptrapd", "pscyber-responder")},
        "wazuh_agent": agent_state(),
        "syslog_sources": sorted(sources, key=lambda s: -s["bytes"])[:50],
        "syslog_source_count": len(sources),
        "snmptrap_log_bytes": traps,
        # Which host types the responder can reach from here: SSH needs paramiko, WinRM pywinrm.
        "responder_libs": {m: _importable(m) for m in ("paramiko", "winrm")},
        # 1.2.0+: this box is the site's Ansible control node (approved playbooks only).
        "ansible": ansible_version(),
        "os": platform.platform(),
        "system": system(),
        "feeds": feeds(),
        "platform_url": platform_url,  # the address this collector reaches the platform at (1.2.4+)
    }
    if os.path.exists(f"{ETC}/platform.pem"):
        # Pinned: only the exact certificate saved at install is trusted. The name
        # check is off because a "public" collector reaches the platform through a
        # NAT address that is not in that certificate - the pin is the stronger check.
        ctx = ssl.create_default_context(cafile=f"{ETC}/platform.pem")
        ctx.check_hostname = False
    else:
        ctx = ssl._create_unverified_context()
    req = urllib.request.Request(
        f"{platform_url}/api/collectors/heartbeat",
        data=json.dumps({"version": open("/opt/pscyber-collector/VERSION").read().strip(), "facts": facts}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {cfg['api_secret']}"}, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
    except urllib.error.URLError as e:
        # The platform now shows a PUBLIC certificate for its name (Certificates page, 1.2.4+): accepted
        # only verified by the system's trusted CAs AND for the platform's hostname - never "any".
        if not isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
            raise
        resp = urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context())
    with resp as r:
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
    want = str(reply.get("platform_url") or "").rstrip("/")
    if want and want != platform_url.rstrip("/"):
        move_platform(cfg, want, ctx)
    if reply.get("update"):
        start_update()


def _reach(url: str, ctx: ssl.SSLContext) -> bool:
    """Can the platform be reached - and trusted - at this address? The same trust as the heartbeat:
    the pinned certificate, or a public one verified by the system CAs for that name."""
    for c in (ctx, ssl.create_default_context()):
        try:
            with urllib.request.urlopen(f"{url}/api/health", timeout=15, context=c) as r:
                return r.status == 200
        except urllib.error.URLError as e:
            if not isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                return False
        except Exception:  # noqa: BLE001
            return False
    return False


def move_platform(cfg: dict, url: str, ctx: ssl.SSLContext) -> None:
    """The SOC chose another address for this collector (private / public by name / public by IP).
    Moved only once the platform answers - and is trusted - there, so a wrong address never cuts the
    collector off: it keeps the old one and the platform shows it has not moved yet."""
    if not url.startswith("https://") or not _reach(url, ctx):
        return
    cfg["platform_url"] = url
    tmp = f"{ETC}/config.json.new"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(cfg, f, indent=1)
    os.replace(tmp, f"{ETC}/config.json")
    with open(f"{ETC}/platform_url.new", "w") as f:
        f.write(url + "\n")
    os.replace(f"{ETC}/platform_url.new", f"{ETC}/platform_url")
    # the responder reads the address on each request; restart it so nothing keeps the old one
    subprocess.run(["systemctl", "restart", "pscyber-responder"], capture_output=True, timeout=30)


def start_update() -> None:
    """The platform's Update button. Hand the work to its OWN transient unit and return:
    update.sh restarts this timer and the responder, and anything inside their cgroups
    would be killed half way through replacing the software. A fixed unit name makes a
    second request while one is running fail instead of racing it. Success is proven by
    the next heartbeat reporting the new version, not by this call."""
    subprocess.run(["systemd-run", "--unit=pscyber-collector-update", "--collect", "--no-block",
                    "/usr/local/sbin/pscyber-collector-update"], capture_output=True, timeout=15)


if __name__ == "__main__":
    main()
