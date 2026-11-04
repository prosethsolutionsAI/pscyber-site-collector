"""Synthetic tests (collector 1.4.0; logins, request bodies and JSON checks 1.5.0; database tests 1.7.0 - a
read-only query run on one of the customer's own hosts): this collector tests the customer's network the way a user would -
ping (latency, jitter, loss), a web page or API (status; DNS / connect / TLS / first-byte time; a keyword),
a DNS lookup (time, the answer), a TCP port (connect time) and the PATH hop by hop (latency and loss at each
hop). The tests come from the platform (POST /api/collectors/synthetic/config - the customer chooses them
in Agentic or its portal); this collector runs them and reports what it measured. The platform judges.

Every target is passed to a tool as an ARGUMENT, never through a shell, and the platform has already
checked it is a host, an address or an http(s) URL. Standard tools only: ping, dig, traceroute.
"""
from __future__ import annotations

import base64
import http.client
import json
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
UA = "PSCyber-Synthetic/1.5"


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
    # bounded counts, not possessive ++: the collector also runs on Python older than 3.11
    sent = re.search(r"\b(\d{1,9}) packets transmitted, (\d{1,9}) (?:packets )?received", out)
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


def _hv(v) -> str:
    """A header value with every CR / LF removed - nothing the platform sends can start a second header."""
    return re.sub(r"[\r\n]", "", str(v or ""))


def _login_headers(c: dict) -> list:
    """1.5.0: the check's login, as the header the API expects. The secret arrives only in this collector's own
    config and is never written to disk or into what is reported."""
    a = c.get("auth") or {}
    kind, secret = a.get("type") or "none", _hv(a.get("secret"))
    if kind == "bearer" and secret:
        return [("Authorization", f"Bearer {secret}")]
    if kind == "basic" and secret:
        raw = f"{_hv(a.get('user'))}:{secret}".encode()
        return [("Authorization", "Basic " + base64.b64encode(raw).decode())]
    name = re.sub(r"[^A-Za-z0-9-]", "", str(a.get("header") or ""))
    if kind == "header" and name and secret:
        return [(name, secret)]
    return []


def _masked(text: str, c: dict) -> str:
    a = c.get("auth") or {}
    s = _hv(a.get("secret"))
    if len(s) >= 4:
        text = text.replace(s, "***")
        text = text.replace(base64.b64encode(f"{_hv(a.get('user'))}:{s}".encode()).decode(), "***")
    return text


def _json_value(doc, path: str):
    """data.items.0.state -> doc['data']['items'][0]['state']; a missing step is (False, None)."""
    cur = doc
    for step in path.split("."):
        if isinstance(cur, dict) and step in cur:
            cur = cur[step]
        elif isinstance(cur, list) and step.isdigit() and int(step) < len(cur):
            cur = cur[int(step)]
        else:
            return False, None
    return True, cur


def _as_text(v) -> str:
    return "true" if v is True else "false" if v is False else "null" if v is None else \
        json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else str(v)


def http_check(c: dict) -> dict:
    r = _http_check(c)
    if r.get("error"):
        r["error"] = _masked(r["error"], c)
    return r


def _http_check(c: dict) -> dict:
    """A request as a browser makes it, timed in its parts: DNS, connect, TLS, first byte, total. From 1.5.0 it
    may log in (Bearer, Basic, an API-key header), use POST/PUT/PATCH with a body, and check one JSON value."""
    o, t = c["options"], int(c["timeout"])
    u = urllib.parse.urlparse(c["target"])
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    method = str(o.get("method") or "GET").upper()
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH"):
        return {"ok": False, "error": f"method {method} is not supported by this collector"}
    payload = str(o.get("body") or "").encode() if method in ("POST", "PUT", "PATCH") else b""
    headers = [("Host", u.netloc), ("User-Agent", UA), ("Accept", "*/*"), ("Connection", "close")]
    if method in ("POST", "PUT", "PATCH"):
        headers += [("Content-Type", o.get("content_type") or "application/json"), ("Content-Length", str(len(payload)))]
    headers += _login_headers(c)
    head = f"{method} {_hv(path)} HTTP/1.1\r\n" + "".join(f"{_hv(k)}: {_hv(v)}\r\n" for k, v in headers) + "\r\n"
    want_body = method != "HEAD" and bool(o.get("keyword") or o.get("json_path"))
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
        sock.sendall(head.encode() + payload)
        t3 = time.perf_counter()
        resp = http.client.HTTPResponse(sock, method=method)
        resp.begin()
        d["ttfb_ms"] = _ms(t3)
        body = resp.read(512 * 1024) if want_body else b""
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
    jp = o.get("json_path") or ""
    if jp and method != "HEAD":
        try:
            doc = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return {"ok": False, "code": code, "latency_ms": total, "error": "the answer is not JSON (or longer than 512 KB)", "detail": d}
        found, val = _json_value(doc, jp)
        if not found:
            return {"ok": False, "code": code, "latency_ms": total, "error": f"the JSON answer has no {jp}", "detail": d}
        exp = str(o.get("json_expect") or "")
        if exp and _as_text(val).strip().lower() != exp.strip().lower():
            return {"ok": False, "code": code, "latency_ms": total,
                    "error": f"{jp} is {_as_text(val)[:80]} - expected {exp[:80]}", "detail": d}
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
        hop, _, rest = line.strip().partition(" ")  # " 3  10.0.0.1  1.2 ms ..." -> "3", "10.0.0.1  1.2 ms ..."
        if not hop.isdigit():
            continue
        ip = next((x for x in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}|(?<![0-9a-f:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}", rest)), "*")
        rtts = [float(x) for x in re.findall(r"\b(\d{1,7}(?:\.\d{1,6})?) ms", rest)]
        stars = rest.count("*")
        probes = len(rtts) + stars or 3
        hops.append({"hop": int(hop), "ip": ip, "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
                     "loss_pct": round(100.0 * stars / probes, 1)})
    if not hops:
        return {"ok": False, "error": "traceroute returned nothing"}
    last = hops[-1]
    if last["ip"] != dest or last["avg_ms"] is None:
        seen = next((h for h in reversed(hops) if h["avg_ms"] is not None), None)
        return {"ok": False, "error": f"the target was not reached in {len(hops)} hops"
                + (f" (last answer: hop {seen['hop']}, {seen['ip']})" if seen else ""), "detail": {"hops": hops}}
    return {"ok": True, "latency_ms": last["avg_ms"], "loss_pct": last["loss_pct"], "detail": {"hops": hops}}


def sql(c: dict) -> dict:
    """1.7.0: a database test. The platform built the script (read-only, per engine) and it carries no secret;
    it runs on the customer's own host (normally the database server) over SSH or WinRM, and the database
    password goes in as the FIRST LINE OF STDIN - never on a command line, never written to disk. This only
    relays what the script printed: the platform parses and judges it."""
    via, secret = c.get("via") or {}, _hv((c.get("auth") or {}).get("secret"))
    deadline = min(int(c.get("timeout") or 10) + 40, 150)   # connect + a rate test's two readings
    try:
        if via.get("transport") == "winrm":
            r = _winrm_stdin(via, str(c.get("script") or ""), secret, deadline)
        else:
            r = _ssh_stdin(via, str(c.get("script") or ""), secret, deadline)
    except Exception as e:  # noqa: BLE001
        r = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    hide = [s for s in (secret, _hv(via.get("password"))) if len(s) >= 4]
    for k in ("output", "error"):
        for s in hide:
            r[k] = str(r.get(k) or "").replace(s, "***")
    r["output"] = r.get("output", "")[-8000:]
    r["error"] = r.get("error", "")[:300]
    return r


def _ssh_stdin(via: dict, script: str, secret: str, deadline: int) -> dict:
    import paramiko
    addr = str(via.get("address") or "")
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(hostname=addr, port=int(via.get("port") or 22), username=via.get("username") or "",
                   password=via.get("password") or None, timeout=15, banner_timeout=15, auth_timeout=15,
                   look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        return {"ok": False, "error": f"{addr} refused the login for '{via.get('username')}'"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"could not reach {addr}: {type(e).__name__}: {e}"}
    try:
        ch = cl.get_transport().open_session()
        ch.set_combine_stderr(True)
        # POSIX sh, whatever the account's login shell is - the script is written for it
        ch.exec_command("/bin/sh -c " + _sh_quote(script))
        ch.sendall((secret + "\n").encode())
        ch.shutdown_write()
        # poll with a wall clock: a blocking recv does not notice the deadline (the responder's lesson)
        end, out = time.monotonic() + deadline, b""
        while True:
            if time.monotonic() > end:
                ch.close()
                return {"ok": False, "output": out.decode("utf-8", "replace"), "error": f"no result from {addr} within {deadline} s"}
            if ch.recv_ready():
                chunk = ch.recv(8192)
                if not chunk:
                    break
                out = (out + chunk)[-200000:]
            elif ch.exit_status_ready():
                break
            else:
                time.sleep(0.05)
        while ch.recv_ready():
            out += ch.recv(8192)
        return {"ok": True, "output": out.decode("utf-8", "replace")}
    finally:
        cl.close()


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# Reads the password (first line) and the script (the rest) from stdin, then runs the script: nothing secret
# and nothing long on the PowerShell command line (which Windows caps at 8191 characters).
_WIN_BOOT = ("[Console]::InputEncoding = [Text.Encoding]::UTF8; $i = [Console]::In.ReadToEnd(); $n = $i.IndexOf(\"`n\"); "
             "$__PW = $i.Substring(0, $n).TrimEnd(\"`r\"); $s = $i.Substring($n + 1); Remove-Variable i; "
             "& ([scriptblock]::Create($s))")


def _winrm_stdin(via: dict, script: str, secret: str, deadline: int) -> dict:
    try:
        from winrm.protocol import Protocol
    except ImportError:
        return {"ok": False, "error": "pywinrm is not installed on the collector - run: sudo pscyber-collector update"}
    addr, port = str(via.get("address") or ""), int(via.get("port") or 5985)
    p = Protocol(endpoint=f"{'https' if port == 5986 else 'http'}://{addr}:{port}/wsman", transport="ntlm",
                 username=via.get("username") or "", password=via.get("password") or "",
                 server_cert_validation="ignore", operation_timeout_sec=20, read_timeout_sec=30)
    if not hasattr(p, "send_command_input"):
        return {"ok": False, "error": "this collector's pywinrm cannot send input - run: sudo pscyber-collector update"}
    box: dict = {}

    def work():
        try:
            shell = p.open_shell(codepage=65001)
            try:
                enc = base64.b64encode(_WIN_BOOT.encode("utf-16-le")).decode()
                cid = p.run_command(shell, "powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", enc])
                p.send_command_input(shell, cid, secret + "\n" + script, end=True)
                out, err, _rc = p.get_command_output(shell, cid)
                p.cleanup_command(shell, cid)
                box["out"] = out.decode("utf-8", "replace") + ("\n" + err.decode("utf-8", "replace") if err and b"<Objs" not in err else "")
            finally:
                p.close_shell(shell)
        except Exception as e:  # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(deadline)
    if t.is_alive():
        return {"ok": False, "error": f"no result from {addr} within {deadline} s"}
    if "e" in box:
        msg = str(box["e"])
        if "401" in msg or "credentials" in msg.lower():
            return {"ok": False, "error": f"{addr} refused the login for '{via.get('username')}'"}
        return {"ok": False, "error": f"could not reach {addr}:{port} over WinRM: {type(box['e']).__name__}: {msg[:200]}"}
    return {"ok": True, "output": box["out"]}


TESTS = {"ping": ping, "tcp": tcp, "http": http_check, "dns": dns, "trace": trace, "sql": sql}


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
        self.running: set = set()       # database tests in flight

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
        # a database test can take a minute (a login, two readings of a counter): it reports on its own and
        # never holds up the pings and web tests of this round
        for c in [c for c in todo if c["kind"] == "sql" and c["id"] not in self.running]:
            self.running.add(c["id"])   # never two logins to the same database at once
            threading.Thread(target=lambda c=c: self._post_one(c), name=f"synthetic-sql-{c['id']}", daemon=True).start()
        todo = [c for c in todo if c["kind"] != "sql"]
        if not todo:
            return
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            results = list(ex.map(run_one, todo))
        for i in range(0, len(results), 50):
            self.post("/api/collectors/synthetic/results", {"results": results[i:i + 50]})

    def _post_one(self, c: dict) -> None:
        try:
            self.post("/api/collectors/synthetic/results", {"results": [run_one(c)]})
        except Exception:  # noqa: BLE001 - a blip; the next run reports again
            pass
        finally:
            self.running.discard(c["id"])

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
