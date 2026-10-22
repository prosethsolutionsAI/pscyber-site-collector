#!/usr/bin/env python3
"""PSCyber collector - SNMP (1.3.0+). Started by the responder; standard library + net-snmp's tools.

  1. Every 2 minutes, ask the platform what to poll: devices, their credential, the trap credentials.
     Managed in Agentic (Network devices). Nothing is configured on this box by hand.
  2. Poll each device on its interval (UDP 161): system info, CPU, memory, disk, sessions, and every
     interface's state and counters. Post the readings; the platform works out the rates.
  3. Hand the trap receiver (snmp_traps.py, UDP 162) the communities / SNMPv3 users it accepts -
     only when Agentic manages this customer's SNMP; otherwise the community chosen at install stays.
  4. Forward each trap the receiver logged (the file is ALSO read by the Wazuh agent, as before).

Secrets: never on a command line (other users on the box could read the process list). Each poll
writes a private snmp.conf (0600, in a 0700 temporary directory removed afterwards) and points the
net-snmp tools at it with SNMPCONFPATH. They are never logged.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor

CONFIG_EVERY = 120
TRAP_LOG = "/var/log/pscyber/snmptraps.log"
TRAP_POS = "/etc/pscyber-collector/snmptraps.pos"
MAX_WORKERS = 8
TIMEOUT = 2          # seconds per request, net-snmp -t
RETRIES = 1
MAX_IFACES = 512

SYS = {"descr": ".1.3.6.1.2.1.1.1.0", "object_id": ".1.3.6.1.2.1.1.2.0", "uptime": ".1.3.6.1.2.1.1.3.0",
       "name": ".1.3.6.1.2.1.1.5.0", "location": ".1.3.6.1.2.1.1.6.0"}
ENGINE_ID = ".1.3.6.1.6.3.10.2.1.1.0"
IF_TABLE = ".1.3.6.1.2.1.2.2.1"        # ifDescr 2, ifSpeed 5, admin 7, oper 8, inOctets 10, inDiscards 13, inErrors 14, outOctets 16, outErrors 20
IFX_TABLE = ".1.3.6.1.2.1.31.1.1.1"    # ifName 1, HCIn 6, HCOut 10, HighSpeed 15, Alias 18
STATUS = {"1": "up", "2": "down", "3": "testing", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}


# --------------------------------------------------------------- net-snmp, without secrets on the command line

def _conf(cred: dict) -> str:
    lines = ["mibs :", "persistentDir {dir}", "showMibErrors no"]
    if cred.get("version") == "3":
        lines += ["defVersion 3", f"defSecurityName {cred.get('user', '')}", f"defSecurityLevel {cred.get('level', 'authPriv')}"]
        if cred.get("level") in ("authNoPriv", "authPriv"):
            lines += [f"defAuthType {cred.get('auth_proto', 'SHA')}", f"defAuthPassphrase {cred.get('auth', '')}"]
        if cred.get("level") == "authPriv":
            lines += [f"defPrivType {cred.get('priv_proto', 'AES')}", f"defPrivPassphrase {cred.get('priv', '')}"]
    else:
        lines += ["defVersion 2c", f"defCommunity {cred.get('community', '')}"]
    return "\n".join(lines) + "\n"


class Snmp:
    """One device's session: a private config directory for the length of one poll."""

    def __init__(self, dev: dict):
        self.target = f"udp:{dev['ip']}:{int(dev.get('port') or 161)}"
        self.dir = tempfile.mkdtemp(prefix="pscyber-snmp-")   # 0700
        path = os.path.join(self.dir, "snmp.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(_conf(dev.get("credential") or {}).replace("{dir}", self.dir))
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SNMPCONFPATH": self.dir, "MIBS": "", "MIBDIRS": self.dir,
                    "HOME": self.dir}

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, tool: str, args: list, timeout: int = 30) -> str:
        cmd = [tool, "-On", "-Oe", "-Oq", "-Ot", "-Oa", "-OU", "-t", str(TIMEOUT), "-r", str(RETRIES), self.target, *args]
        p = subprocess.run(cmd, env=self.env, capture_output=True, text=True, timeout=timeout, errors="replace")
        if p.returncode != 0 and not p.stdout.strip():
            err = (p.stderr or "").strip().splitlines()
            raise RuntimeError(err[-1] if err else f"{tool} failed")
        return p.stdout

    def get(self, oids: list) -> dict:
        return _parse(self._run("snmpget", oids))

    def walk(self, base: str, timeout: int = 60) -> dict:
        try:
            out = self._run("snmpbulkwalk", ["-Cr30", base], timeout=timeout)
        except RuntimeError:
            return {}
        return {k[len(base) + 1:]: v for k, v in _parse(out).items() if k.startswith(base + ".")}


_MISSING = ("No Such Object", "No Such Instance", "No more variables")


def _parse(text: str) -> dict:
    out: dict = {}
    open_str = None                             # an OID whose quoted string has not closed yet
    for line in text.splitlines():
        if open_str is not None:                # a multi-line string (sysDescr often is)
            closed = line.rstrip().endswith('"')
            out[open_str] = (out[open_str] + " " + line.strip().rstrip('"')).strip()
            if closed:
                open_str = None
            continue
        if not line.startswith("."):
            continue                            # anything else the tool prints ("Created directory: ...")
        oid, _, val = line.partition(" ")
        val = val.strip()
        if any(m in val for m in _MISSING):
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        elif val.startswith('"'):
            val, open_str = val[1:], oid
        out[oid] = val
    return out


def _f(v):
    try:
        return float(str(v).split()[0])
    except (TypeError, ValueError, IndexError):
        return None


def _i(v):
    x = _f(v)
    return int(x) if x is not None else None


def _avg(values) -> float | None:
    xs = [x for x in (_f(v) for v in values) if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


# --------------------------------------------------------------- one poll

def _vendor_metrics(s: Snmp, oid: str) -> dict:
    """CPU / memory / disk / sessions: the vendor's own MIB first, then the standard ones."""
    out: dict = {"sources": {}}
    if oid.startswith(".1.3.6.1.4.1.12356."):                     # Fortinet (FortiGate)
        g = s.get([".1.3.6.1.4.1.12356.101.4.1.3.0", ".1.3.6.1.4.1.12356.101.4.1.4.0", ".1.3.6.1.4.1.12356.101.4.1.5.0",
                   ".1.3.6.1.4.1.12356.101.4.1.6.0", ".1.3.6.1.4.1.12356.101.4.1.7.0", ".1.3.6.1.4.1.12356.101.4.1.8.0",
                   ".1.3.6.1.4.1.12356.101.4.1.1.0", ".1.3.6.1.4.1.12356.100.1.1.1.0"])
        cpu, mem = _f(g.get(".1.3.6.1.4.1.12356.101.4.1.3.0")), _f(g.get(".1.3.6.1.4.1.12356.101.4.1.4.0"))
        if cpu is not None:
            out.update(cpu=cpu, sources={"cpu": "FORTINET-FORTIGATE-MIB"})
        if mem is not None:
            out["mem"] = mem
            out["sources"]["mem"] = "FORTINET-FORTIGATE-MIB"
            if g.get(".1.3.6.1.4.1.12356.101.4.1.5.0"):
                out["mem_total"] = f"{_i(g['.1.3.6.1.4.1.12356.101.4.1.5.0']) // 1024} MB"
        used, cap = _f(g.get(".1.3.6.1.4.1.12356.101.4.1.6.0")), _f(g.get(".1.3.6.1.4.1.12356.101.4.1.7.0"))
        if used is not None and cap:
            out["disk"] = round(100 * used / cap, 1)
        if g.get(".1.3.6.1.4.1.12356.101.4.1.8.0") is not None:
            out["sessions"] = _i(g[".1.3.6.1.4.1.12356.101.4.1.8.0"])
        out["firmware"] = g.get(".1.3.6.1.4.1.12356.101.4.1.1.0") or None
        out["serial"] = g.get(".1.3.6.1.4.1.12356.100.1.1.1.0") or None
    elif oid.startswith(".1.3.6.1.4.1.9."):                       # Cisco
        cpu = _avg(s.walk(".1.3.6.1.4.1.9.9.109.1.1.1.1.8").values()) or _avg(s.walk(".1.3.6.1.4.1.9.9.109.1.1.1.1.5").values())
        if cpu is not None:
            out.update(cpu=cpu, sources={"cpu": "CISCO-PROCESS-MIB"})
        used, free = s.walk(".1.3.6.1.4.1.9.9.48.1.1.1.5"), s.walk(".1.3.6.1.4.1.9.9.48.1.1.1.6")
        if used.get("1") and free.get("1"):
            u, f_ = _f(used["1"]), _f(free["1"])
            if u is not None and f_ is not None and u + f_ > 0:
                out["mem"] = round(100 * u / (u + f_), 1)
                out["sources"]["mem"] = "CISCO-MEMORY-POOL-MIB"
    elif oid.startswith(".1.3.6.1.4.1.2636."):                    # Juniper: the busiest component
        cpu = [x for x in (_f(v) for v in s.walk(".1.3.6.1.4.1.2636.3.1.13.1.8").values()) if x]
        buf = [x for x in (_f(v) for v in s.walk(".1.3.6.1.4.1.2636.3.1.13.1.11").values()) if x]
        if cpu:
            out.update(cpu=max(cpu), sources={"cpu": "JUNIPER-MIB"})
        if buf:
            out["mem"] = max(buf)
            out["sources"]["mem"] = "JUNIPER-MIB"
    elif oid.startswith(".1.3.6.1.4.1.25461."):                   # Palo Alto: sessions (CPU/RAM: HOST-RESOURCES)
        g = s.get([".1.3.6.1.4.1.25461.2.1.2.3.3.0"])
        if g.get(".1.3.6.1.4.1.25461.2.1.2.3.3.0") is not None:
            out["sessions"] = _i(g[".1.3.6.1.4.1.25461.2.1.2.3.3.0"])
    if out.get("cpu") is None:                                    # standard: HOST-RESOURCES, then UCD (Linux)
        cpu = _avg(s.walk(".1.3.6.1.2.1.25.3.3.1.2").values())
        if cpu is None:
            idle = _f(s.get([".1.3.6.1.4.1.2021.11.11.0"]).get(".1.3.6.1.4.1.2021.11.11.0"))
            if idle is not None:
                cpu, out["sources"]["cpu"] = round(100 - idle, 1), "UCD-SNMP-MIB"
        else:
            out["sources"]["cpu"] = "HOST-RESOURCES-MIB"
        out["cpu"] = cpu
    if out.get("mem") is None:
        u = s.get([".1.3.6.1.4.1.2021.4.5.0", ".1.3.6.1.4.1.2021.4.6.0", ".1.3.6.1.4.1.2021.4.14.0", ".1.3.6.1.4.1.2021.4.15.0"])
        total = _f(u.get(".1.3.6.1.4.1.2021.4.5.0"))
        if total:                                                # Linux: used = total - free - buffers - cache
            used = total - sum(_f(u.get(k)) or 0 for k in (".1.3.6.1.4.1.2021.4.6.0", ".1.3.6.1.4.1.2021.4.14.0", ".1.3.6.1.4.1.2021.4.15.0"))
            out["mem"], out["sources"]["mem"] = round(100 * max(0.0, used) / total, 1), "UCD-SNMP-MIB"
            out["mem_total"] = f"{int(total) // 1024} MB"
        else:
            st = s.walk(".1.3.6.1.2.1.25.2.3.1")
            for idx in {k.split(".", 1)[1] for k in st if k.startswith("2.")}:
                if st.get(f"2.{idx}") == ".1.3.6.1.2.1.25.2.1.2":   # hrStorageRam
                    size, used = _f(st.get(f"5.{idx}")), _f(st.get(f"6.{idx}"))
                    if size:
                        out["mem"], out["sources"]["mem"] = round(100 * (used or 0) / size, 1), "HOST-RESOURCES-MIB"
                    break
    return out


def _interfaces(s: Snmp) -> list:
    t, x = s.walk(IF_TABLE), s.walk(IFX_TABLE)
    idxs = sorted({int(k.split(".", 1)[1]) for k in t if k.startswith("2.") and k.split(".", 1)[1].isdigit()})[:MAX_IFACES]
    out = []
    for i in idxs:
        hc_in, hc_out = x.get(f"6.{i}"), x.get(f"10.{i}")
        hc = hc_in is not None and hc_out is not None
        high = _i(x.get(f"15.{i}"))
        speed = high if high else (_i(t.get(f"5.{i}")) or 0) // 1_000_000 or None
        out.append({"i": i, "name": x.get(f"1.{i}") or t.get(f"2.{i}") or f"if{i}", "alias": x.get(f"18.{i}") or "",
                    "speed_mbps": speed, "admin": STATUS.get(t.get(f"7.{i}", ""), t.get(f"7.{i}", "")),
                    "oper": STATUS.get(t.get(f"8.{i}", ""), t.get(f"8.{i}", "")), "hc": hc,
                    "in": _i(hc_in if hc else t.get(f"10.{i}")), "out": _i(hc_out if hc else t.get(f"16.{i}")),
                    "in_err": _i(t.get(f"14.{i}")), "out_err": _i(t.get(f"20.{i}")), "in_disc": _i(t.get(f"13.{i}"))})
    return out


def poll(dev: dict) -> dict:
    s = Snmp(dev)
    try:
        try:
            g = s.get(list(SYS.values()))
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return {"device_id": dev["id"], "ok": False, "error": _why(str(e))}
        if not g:
            return {"device_id": dev["id"], "ok": False, "error": "the device answered with no system information"}
        sysd = {k: g.get(v) for k, v in SYS.items()}
        try:
            eid = s.get([ENGINE_ID]).get(ENGINE_ID) if (dev.get("credential") or {}).get("version") == "3" else None
        except (RuntimeError, subprocess.TimeoutExpired):
            eid = None
        res = {"device_id": dev["id"], "ok": True, "at": time.time(),
               "sys": {"descr": sysd["descr"], "object_id": sysd["object_id"], "name": sysd["name"],
                       "location": sysd["location"], "engine_id": eid},
               "uptime_s": (_i(sysd["uptime"]) or 0) // 100 if sysd["uptime"] else None}
        try:
            res.update(_vendor_metrics(s, sysd["object_id"] or ""))
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        try:
            res["ifaces"] = _interfaces(s)
        except (RuntimeError, subprocess.TimeoutExpired):
            res["ifaces"] = []
        return res
    finally:
        s.close()


def _why(err: str) -> str:
    e = err.lower()
    if "timeout" in e:
        return ("no answer on UDP 161 - check SNMP is enabled on the device for this collector's address, the community / "
                "v3 user matches, and no firewall blocks it")
    if "authentication" in e or "unknown user" in e:
        return "the device refused the SNMPv3 user or its passwords"
    if "decryption" in e:
        return "the SNMPv3 privacy (encryption) password or protocol does not match the device"
    return err[:250]


# --------------------------------------------------------------- traps the receiver logged (snmp_traps.py)

_FROM = re.compile(r"\[(?:UDP|TCP)(?:/IPv6)?: \[([^\]]+)\]")


def read_traps(max_lines: int = 1000) -> tuple[list, dict]:
    """New lines of the trap log since the saved position (a new file starts from its end)."""
    try:
        st = os.stat(TRAP_LOG)
    except OSError:
        return [], {}
    try:
        pos = json.load(open(TRAP_POS))
    except (OSError, ValueError):
        pos = {"ino": st.st_ino, "off": st.st_size}            # first run: do not resend old traps
    if pos.get("ino") != st.st_ino or pos.get("off", 0) > st.st_size:
        pos = {"ino": st.st_ino, "off": 0}                     # rotated
    traps = []
    with open(TRAP_LOG, "rb") as f:
        f.seek(pos["off"])
        for _ in range(max_lines):
            raw = f.readline()
            if not raw or not raw.endswith(b"\n"):
                break
            pos["off"] = f.tell()
            line = raw.decode("utf-8", "replace").strip()
            if "TRAP from" not in line:
                continue
            m = _FROM.search(line)
            traps.append({"at": time.time(), "from_ip": m.group(1) if m else "", "text": line[line.find("TRAP from"):][:4000]})
    return traps, pos


def _save_pos(pos: dict) -> None:
    if pos:
        tmp = TRAP_POS + ".tmp"
        with open(tmp, "w") as f:
            json.dump(pos, f)
        os.replace(tmp, TRAP_POS)


# --------------------------------------------------------------- the loop

class Poller:
    def __init__(self, post, receiver=None):
        self.post = post            # post(path, body) -> dict, on the responder's pinned channel
        self.receiver = receiver    # snmp_traps.TrapReceiver: takes the trap credentials
        self.cfg_only = False       # no net-snmp tools: keep the trap credentials current, poll nothing
        self.cfg: dict = {}
        self.hash = ""
        self.next_cfg = 0.0
        self.due: dict = {}
        self.disabled_until = 0.0

    def _config(self) -> None:
        try:
            got = self.post("/api/collectors/snmp/config", {"have": self.hash})
        except urllib.error.HTTPError as e:
            if e.code == 404:       # an older platform: try again in an hour
                self.disabled_until = time.monotonic() + 3600
            return
        if got.get("unchanged"):
            return
        self.cfg, self.hash = got, got.get("hash", "")
        ids = {d["id"] for d in got.get("devices") or []}
        self.due = {k: v for k, v in self.due.items() if k in ids}
        if got.get("managed") and self.receiver is not None:
            self.receiver.set_credentials(got.get("traps") or [])

    def tick(self) -> None:
        now = time.monotonic()
        if now < self.disabled_until:
            return
        if now >= self.next_cfg:
            self.next_cfg = now + CONFIG_EVERY
            self._config()
        devs = [] if self.cfg_only else [d for d in self.cfg.get("devices") or [] if self.due.get(d["id"], 0) <= now]
        if devs:
            for d in devs:
                self.due[d["id"]] = now + max(30, int(d.get("interval") or 60))
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                results = list(ex.map(poll, devs))
            for i in range(0, len(results), 50):
                self.post("/api/collectors/snmp/results", {"results": results[i:i + 50]})
        traps, pos = read_traps()
        if traps:
            self.post("/api/collectors/snmp/traps", {"traps": traps})
        _save_pos(pos)              # only after the platform took them

    def run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - a blip; SNMP must never stop the responder
                pass
            time.sleep(5)


def start(post) -> threading.Thread:
    """Traps (own receiver on UDP 162) and polling (net-snmp's tools). Without the tools only the
    polling waits for the next update; traps still run."""
    receiver = None
    try:
        import snmp_traps
        receiver = snmp_traps.TrapReceiver()
        receiver.start()
    except Exception:  # noqa: BLE001 - polling still runs
        receiver = None
    poller = Poller(post, receiver)
    if not shutil.which("snmpget"):
        poller.cfg_only = True
    t = threading.Thread(target=poller.run, name="snmp", daemon=True)
    t.start()
    return t
