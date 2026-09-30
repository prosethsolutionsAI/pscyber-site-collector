#!/usr/bin/env python3
"""PSCyber collector RESPONDER: the collector as a worker.

It claims jobs the SOC platform queued for this site, runs each against a host the
site owns, and posts the result back - all on the same outbound, CA-pinned HTTPS
channel the heartbeat uses. The platform decides WHAT; this only carries it out,
inside the customer network where a private address is meaningful.

Same shape as the Engineer System worker: the platform chooses the job id, the
credential arrives in the claim reply and is never written to disk, and a job that
fails returns a readable reason rather than a stack trace.

Runs as a long-lived service, polling every few seconds. Standard library, plus
paramiko for SSH (installed by install.sh).
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from time import monotonic

ETC = "/etc/pscyber-collector"
POLL_IDLE = 5      # seconds between polls when there was no work
POLL_BUSY = 1      # poll again quickly right after doing something


def _cfg() -> dict:
    return json.load(open(f"{ETC}/config.json"))


def _ctx() -> ssl.SSLContext:
    if os.path.exists(f"{ETC}/platform.pem"):
        ctx = ssl.create_default_context(cafile=f"{ETC}/platform.pem")
        ctx.check_hostname = False  # a public collector reaches a NAT address not in the cert; the pin is the check
        return ctx
    return ssl._create_unverified_context()


def _post(path: str, body: dict, cfg: dict, ctx: ssl.SSLContext) -> dict:
    url = (cfg.get("platform_url") or open(f"{ETC}/platform_url").read().strip()) + path
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {cfg['api_secret']}"}, method="POST")
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read() or b"{}")


# --------------------------------------------------------------- executors

# One line, ';'-separated: run as the ssh command directly, which is fast and reliable against
# the UAT host (a multi-line body was not). No `hostname -f` - the FQDN form does a reverse-DNS
# lookup that hangs where DNS is slow or absent (seen live). Plain `hostname` never touches DNS.
FACTS = ("echo hostname=$(hostname 2>/dev/null); echo kernel=$(uname -r 2>/dev/null); "
         ". /etc/os-release 2>/dev/null; echo distro=$NAME; echo version=$VERSION_ID; "
         "echo cpus=$(nproc 2>/dev/null); "
         "echo memory_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)")


def _ssh_run(target: dict, script: str | None, timeout: int = 120) -> dict:
    """Run a command on the host over SSH and return its output. Nothing is written to
    the host; the password goes to paramiko, never to a log. script=None only proves the
    login (network devices: their CLI is not a shell, so FACTS means nothing there)."""
    import paramiko
    address = str(target.get("address") or "").strip()
    if not address:
        return {"ok": False, "output": "", "error": "no host address in the job"}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=address, port=int(target.get("port") or 22),
                       username=target.get("username") or "", password=target.get("password") or None,
                       timeout=20, banner_timeout=20, auth_timeout=20, look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        return {"ok": False, "output": "", "error": f"{address} refused the login for '{target.get('username')}'"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "output": "", "error": f"could not reach {address}: {type(e).__name__}: {e}"}
    if script is None:
        client.close()
        return {"ok": True, "exit_code": 0, "output": "", "error": ""}
    try:
        chan = client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.set_combine_stderr(True)
        # Run the script as the command itself (sshd runs it via the login shell's -c),
        # not piped into `bash -s` over stdin: the stdin-EOF handshake did not make the
        # remote shell exit against the UAT host, so recv never saw the channel close.
        chan.exec_command(script)
        # Poll, do not block: the deadline is enforced HERE. A blocking recv() does not
        # notice the channel finishing and can spin past its own timeout (seen live against
        # the UAT host). recv_ready()/exit_status_ready() + a wall clock is the proven shape.
        deadline = monotonic() + timeout
        out = b""
        while True:
            if monotonic() > deadline:
                chan.close()
                return {"ok": False, "output": out.decode("utf-8", "replace")[:20000],
                        "error": f"no output and no exit after {timeout}s on {address} - abandoned"}
            if chan.recv_ready():
                chunk = chan.recv(8192)
                if not chunk:
                    break
                out += chunk
                if len(out) > 1_000_000:
                    break
            elif chan.exit_status_ready():
                break
            else:
                time.sleep(0.05)
        while chan.recv_ready():
            out += chan.recv(8192)
        code = chan.recv_exit_status()
        return {"ok": code == 0, "exit_code": code, "output": out.decode("utf-8", "replace")[:20000], "error": ""}
    finally:
        client.close()


def _parse_facts(text: str) -> dict:
    facts: dict = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() and v.strip() and " " not in k.strip():
            facts[k.strip()] = v.strip()
    for k in ("cpus", "memory_mb"):
        if k in facts:
            try:
                facts[k] = int(facts[k])
            except ValueError:
                pass
    return facts


# Windows facts, one PowerShell line. DomainRole 4/5 = a domain controller (AD).
WIN_FACTS = ("$o=Get-CimInstance Win32_OperatingSystem; $c=Get-CimInstance Win32_ComputerSystem; "
             "'hostname=' + $env:COMPUTERNAME; 'distro=' + $o.Caption; 'version=' + $o.Version; "
             "'cpus=' + $c.NumberOfLogicalProcessors; 'memory_mb=' + [int]($c.TotalPhysicalMemory/1MB); "
             "'domain=' + $c.Domain; 'domain_role=' + $c.DomainRole")
# pywinrm sends PowerShell as -EncodedCommand (UTF-16, base64) and Windows caps a command
# line at 8191 characters - about 3000 characters of script. Refuse beyond it, readably.
WINRM_MAX_SCRIPT = 2800


def _winrm_run(target: dict, script: str, timeout: int = 120) -> dict:
    """Run PowerShell on a Windows host over WinRM (NTLM, message-encrypted on 5985;
    5986 = HTTPS, certificate not validated - the same trust-on-first-use as SSH)."""
    import threading
    address = str(target.get("address") or "").strip()
    if not address:
        return {"ok": False, "output": "", "error": "no host address in the job"}
    if len(script) > WINRM_MAX_SCRIPT:
        return {"ok": False, "output": "", "error": f"script is {len(script)} characters; WinRM through the collector takes up to {WINRM_MAX_SCRIPT}"}
    try:
        import winrm
    except ImportError:
        return {"ok": False, "output": "", "error": "pywinrm is not installed on the collector - run: sudo pscyber-collector update"}
    port = int(target.get("port") or 5985)
    scheme = "https" if port == 5986 else "http"
    box: dict = {}

    def work():
        try:
            s = winrm.Session(f"{scheme}://{address}:{port}/wsman", auth=(target.get("username") or "", target.get("password") or ""),
                              transport="ntlm", server_cert_validation="ignore",
                              operation_timeout_sec=20, read_timeout_sec=30)
            box["r"] = s.run_ps(script)
        except Exception as e:  # noqa: BLE001
            box["e"] = e

    # pywinrm polls the command for as long as it runs; the deadline is enforced HERE.
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {"ok": False, "output": "", "error": f"no result after {timeout}s from {address} - abandoned"}
    if "e" in box:
        e = box["e"]
        msg = str(e)
        if "401" in msg or "credentials" in msg.lower():
            return {"ok": False, "output": "", "error": f"{address} refused the login for '{target.get('username')}'"}
        return {"ok": False, "output": "", "error": f"could not reach {address}:{port} over WinRM: {type(e).__name__}: {msg[:300]}"}
    r = box["r"]
    out = (r.std_out or b"").decode("utf-8", "replace")
    err = (r.std_err or b"").decode("utf-8", "replace")
    if err.strip() and "<Objs" in err:  # PowerShell CLIXML progress noise, not an error
        err = ""
    text = (out + ("\n" + err if err.strip() else ""))[:20000]
    return {"ok": r.status_code == 0, "exit_code": r.status_code, "output": text, "error": ""}


def run_job(job: dict) -> dict:
    """Dispatch one claimed job to its executor. Returns {status, result, output}."""
    action = job.get("action")
    target = job.get("target") or {}
    transport = target.get("transport") or "ssh"
    network = job.get("connector") == "network_ssh"
    if transport not in ("ssh", "winrm"):
        return {"status": "failed", "result": {"error": f"this collector version cannot do '{transport}' yet"}, "output": ""}
    execute = _winrm_run if transport == "winrm" else _ssh_run
    if action == "probe":
        facts_cmd = WIN_FACTS if transport == "winrm" else (None if network else FACTS)
        r = execute(target, facts_cmd)
        if not r["ok"]:
            return {"status": "failed", "result": {"error": r["error"] or f"exit code {r.get('exit_code')}"}, "output": r["output"]}
        facts = _parse_facts(r["output"]) if facts_cmd else {"login": "ok"}
        return {"status": "done", "result": facts, "output": r["output"]}
    if action == "run":
        script = (job.get("params") or {}).get("script") or ""
        if not script.strip():
            return {"status": "failed", "result": {"error": "no command supplied"}, "output": ""}
        r = execute(target, script, timeout=int((job.get("params") or {}).get("timeout") or 300))
        # Many network CLIs report no exit status (-1) for a command that worked: there,
        # only a transport error is a failure.
        ok = r["ok"] or (network and not r.get("error"))
        return {"status": "done" if ok else "failed",
                "result": {"exit_code": r.get("exit_code"), "error": r.get("error", "")}, "output": r["output"]}
    return {"status": "failed", "result": {"error": f"unknown action '{action}'"}, "output": ""}


def main() -> None:
    ctx = _ctx()
    while True:
        delay = POLL_IDLE
        try:
            cfg = _cfg()
            jobs = _post("/api/collectors/jobs/claim", {}, cfg, ctx).get("jobs") or []
            for job in jobs:
                delay = POLL_BUSY
                try:
                    res = run_job(job)
                except Exception as e:  # noqa: BLE001 - one bad job must not kill the loop
                    res = {"status": "failed", "result": {"error": f"{type(e).__name__}: {e}"}, "output": ""}
                try:
                    _post(f"/api/collectors/jobs/{job['id']}/result", res, cfg, ctx)
                except Exception:  # noqa: BLE001 - the platform expires an unresulted job; try again next loop
                    pass
        except urllib.error.URLError:
            delay = POLL_IDLE  # platform unreachable; keep trying quietly
        except Exception:  # noqa: BLE001
            delay = POLL_IDLE
        time.sleep(delay)


if __name__ == "__main__":
    main()
