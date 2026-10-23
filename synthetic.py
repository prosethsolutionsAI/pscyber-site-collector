"""Synthetic tests (collector 1.4.0): this collector tests the customer's network the way a user would -
ping (latency, jitter, loss), a web page or API (status; DNS / connect / TLS / first-byte time; a keyword),
a DNS lookup (time, the answer), a TCP port (connect time) and the PATH hop by hop (latency and loss at each
hop). The tests come from the platform (POST /api/collectors/synthetic/config - the customer chooses them
in Agentic or its portal); this collector runs them and reports what it measured. The platform judges.

Every target is passed to a tool as an ARGUMENT, never through a shell, and the platform has already
checked it is a host, an address or an http(s) URL. Standard tools only: ping, dig, traceroute.
"""
from __future__ import annotations

import http.client
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

CONFIG_EVERY = 60
MAX_WORKERS = 8
UA = "PSCyber-Synthetic/1.4"


def _run(args: list, timeout: float) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return ""


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


# --------------------------------------------------------------- the tests

def ping(c: dict) -> dict:
    if not shutil.which("ping"):
        return {"ok": False, "error": "ping is not installed on the collector"}
    n, t = int(c["options"].get("count") or 5), int(c["timeout"])
    out = _run(["ping", "-n", "-c", str(n), "-i", "0.2", "-W", str(t), c["target"]], n * (t + 1) + 10)
    sent = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if not sent:
        msg = out.strip().splitlines()[-1] if out.strip() else "no answer"
        return {"ok": False, "loss_pct": 100.0, "error": msg[:200]}
    tx, rx = int(sent.group(1)), int(sent.group(2))
    loss = round(100.0 * (tx - rx) / tx, 1) if tx else 100.0
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    if not rx or not rtt:
        return {"ok": False, "loss_pct": 100.0, "error": f"no reply to {tx} pings"}
    return {"ok": True, "latency_ms": float(rtt.group(2)), "jitter_ms": float(rtt.group(4)), "loss_pct": loss,
            "detail": {"min_ms": float(rtt.group(1)), "max_ms": float(rtt.group(3))}}


def tcp(c: dict) -> dict:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((c["target"], int(c["port"])), timeout=int(c["timeout"])):
            return {"ok": True, "latency_ms": _ms(t0)}
    except socket.timeout:
        return {"ok": False, "error": f"no answer on port {c['port']} within {c['timeout']} s"}
    except ConnectionRefusedError:
        return {"ok": False, "error": f"port {c['port']} refused the connection (nothing listening, or a firewall)"}
    except OSError as e:
        return {"ok": False, "error": str(e)[:200]}


def _expected(code: int, spec: str) -> bool:
    for part in (spec or "200-399").split(","):
        lo, _, hi = part.partition("-")
        if int(lo) <= code <= int(hi or lo):
            return True
    return False


def http_check(c: dict) -> dict:
    """A request as a browser makes it, timed in its parts: DNS, connect, TLS, first byte, total."""
    o, t = c["options"], int(c["timeout"])
    u = urllib.parse.urlparse(c["target"])
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    d: dict = {}
    t0 = time.perf_counter()
    try:
        info = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)
        d["dns_ms"] = _ms(t0)
        d["resolved"] = info[0][4][0]
        t1 = time.perf_counter()
        sock = socket.create_connection((info[0][4][0], port), timeout=t)
        d["connect_ms"] = _ms(t1)
        if https:
            t2 = time.perf_counter()
            ctx = ssl.create_default_context()
            if not o.get("verify_tls", True):
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
            d["tls_ms"] = _ms(t2)
            cert = sock.getpeercert() if o.get("verify_tls", True) else None
            if cert and cert.get("notAfter"):
                d["cert_days"] = round((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400, 1)
        method = o.get("method") or "GET"
        sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        t3 = time.perf_counter()
        resp = http.client.HTTPResponse(sock, method=method)
        resp.begin()
        d["ttfb_ms"] = _ms(t3)
        body = resp.read(512 * 1024) if method == "GET" and o.get("keyword") else b""
        sock.close()
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"certificate not trusted: {getattr(e, 'verify_message', '') or e}"[:200], "detail": d}
    except socket.timeout:
        return {"ok": False, "error": f"no answer within {t} s", "detail": d}
    except (OSError, http.client.HTTPException) as e:
        return {"ok": False, "error": str(e)[:200] or e.__class__.__name__, "detail": d}
    total = _ms(t0)
    d["total_ms"] = total
    code = resp.status
    if not _expected(code, o.get("expect") or "200-399"):
        return {"ok": False, "code": code, "latency_ms": total, "error": f"HTTP {code} (expected {o.get('expect') or '200-399'})", "detail": d}
    kw = o.get("keyword") or ""
    if kw and kw.lower() not in body.decode("utf-8", "replace").lower():
        return {"ok": False, "code": code, "latency_ms": total, "error": f"the page does not contain '{kw}'", "detail": d}
    return {"ok": True, "code": code, "latency_ms": total, "detail": d}


def dns(c: dict) -> dict:
    o, t = c["options"], int(c["timeout"])
    rec = o.get("record") or "A"
    if not shutil.which("dig"):
        if rec not in ("A", "AAAA") or o.get("server"):
            return {"ok": False, "error": "dig is not installed on the collector (dnsutils)"}
        t0 = time.perf_counter()
        try:
            fam = socket.AF_INET if rec == "A" else socket.AF_INET6
            ans = sorted({i[4][0] for i in socket.getaddrinfo(c["target"], None, fam)})
        except OSError as e:
            return {"ok": False, "error": str(e)[:200]}
        return _dns_result(_ms(t0), ans, o)
    args = ["dig", "+tries=1", f"+time={t}"] + ([f"@{o['server']}"] if o.get("server") else []) + [c["target"], rec]
    out = _run(args, t + 5)
    status = re.search(r"status: (\w+)", out)
    qtime = re.search(r"Query time: (\d+) msec", out)
    if not status:
        return {"ok": False, "error": "no answer from the DNS server" if "timed out" in out or not out else out.strip().splitlines()[-1][:200]}
    if status.group(1) != "NOERROR":
        return {"ok": False, "latency_ms": float(qtime.group(1)) if qtime else None, "error": f"DNS {status.group(1)}"}
    sect = out.split(";; ANSWER SECTION:", 1)
    ans = []
    if len(sect) == 2:
        for line in sect[1].split("\n\n", 1)[0].strip().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ans.append(" ".join(parts[4:]))
    return _dns_result(float(qtime.group(1)) if qtime else None, ans, o)


def _dns_result(ms, ans: list, o: dict) -> dict:
    if not ans:
        return {"ok": False, "latency_ms": ms, "error": "the name resolved to nothing", "detail": {"answers": []}}
    exp = (o.get("expect") or "").strip()
    if exp and not any(exp.lower() in a.lower() for a in ans):
        return {"ok": False, "latency_ms": ms, "error": f"answer is {', '.join(ans[:3])} - expected {exp}", "detail": {"answers": ans}}
    return {"ok": True, "latency_ms": ms, "detail": {"answers": ans}}


def trace(c: dict) -> dict:
    """The path hop by hop - latency and loss at each hop (3 probes per hop, ICMP)."""
    if not shutil.which("traceroute"):
        return {"ok": False, "error": "traceroute is not installed on the collector"}
    hops_max = int(c["options"].get("max_hops") or 20)
    w = max(1, min(int(c["timeout"]), 3))
    out = _run(["traceroute", "-I", "-n", "-q", "3", "-w", str(w), "-m", str(hops_max), c["target"]], min(hops_max * 3 * w + 15, 180))
    try:
        dest = socket.gethostbyname(c["target"])
    except OSError:
        return {"ok": False, "error": f"cannot resolve {c['target']}"}
    hops = []
    for line in out.splitlines()[1:]:
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        ip = next((x for x in re.findall(r"\d+\.\d+\.\d+\.\d+|[0-9a-f:]+:[0-9a-f:]+", rest)), "*")
        rtts = [float(x) for x in re.findall(r"([\d.]+) ms", rest)]
        stars = rest.count("*")
        probes = len(rtts) + stars or 3
        hops.append({"hop": int(m.group(1)), "ip": ip, "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
                     "loss_pct": round(100.0 * stars / probes, 1)})
    if not hops:
        return {"ok": False, "error": "traceroute returned nothing"}
    last = hops[-1]
    if last["ip"] != dest or last["avg_ms"] is None:
        seen = next((h for h in reversed(hops) if h["avg_ms"] is not None), None)
        return {"ok": False, "error": f"the target was not reached in {len(hops)} hops"
                + (f" (last answer: hop {seen['hop']}, {seen['ip']})" if seen else ""), "detail": {"hops": hops}}
    return {"ok": True, "latency_ms": last["avg_ms"], "loss_pct": last["loss_pct"], "detail": {"hops": hops}}


TESTS = {"ping": ping, "tcp": tcp, "http": http_check, "dns": dns, "trace": trace}


def run_one(c: dict) -> dict:
    try:
        r = TESTS[c["kind"]](c)
    except Exception as e:  # noqa: BLE001 - one test never stops the others
        r = {"ok": False, "error": f"the test failed on the collector: {e}"[:200]}
    r["id"] = c["id"]
    return r


# --------------------------------------------------------------- the loop

class Prober:
    def __init__(self, post):
        self.post = post            # post(path, body) -> dict, on the responder's pinned channel
        self.checks: list = []
        self.hash = ""
        self.next_cfg = 0.0
        self.due: dict = {}
        self.disabled_until = 0.0

    def _config(self) -> None:
        try:
            got = self.post("/api/collectors/synthetic/config", {"have": self.hash})
        except urllib.error.HTTPError as e:
            if e.code == 404:       # an older platform: try again in an hour
                self.disabled_until = time.monotonic() + 3600
            return
        if got.get("unchanged"):
            return
        self.checks, self.hash = list(got.get("checks") or []), got.get("hash", "")
        ids = {c["id"] for c in self.checks}
        self.due = {k: v for k, v in self.due.items() if k in ids}

    def tick(self) -> None:
        now = time.monotonic()
        if now < self.disabled_until:
            return
        if now >= self.next_cfg:
            self.next_cfg = now + CONFIG_EVERY
            self._config()
        todo = [c for c in self.checks if self.due.get(c["id"], 0) <= now]
        if not todo:
            return
        for c in todo:
            self.due[c["id"]] = now + max(30, int(c.get("interval") or 60))
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            results = list(ex.map(run_one, todo))
        for i in range(0, len(results), 50):
            self.post("/api/collectors/synthetic/results", {"results": results[i:i + 50]})

    def run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - a blip; tests must never stop the responder
                pass
            time.sleep(5)


def start(post) -> threading.Thread:
    t = threading.Thread(target=Prober(post).run, name="synthetic", daemon=True)
    t.start()
    return t
