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
paramiko for SSH, pywinrm for WinRM, and (1.2.0+) ansible-core + sshpass so this box
is the site's Ansible control node for approved playbooks (installed by update.sh).
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


PROGRESS_EVERY = 2  # seconds between live-output posts while a command runs


def _txt(out: bytes) -> str:
    return out.decode("utf-8", "replace").replace("\r\n", "\n")  # a pty ends lines with CRLF


def _ssh_run(target: dict, script: str | None, timeout: int = 120, progress=None) -> dict:
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
        if progress:
            # A terminal for a Run command, so Stop / the time limit really END it: closing a
            # pty hangs the command up (SIGHUP). Without one, a command that prints nothing
            # (sleep 600) carries on on the host after the session is gone.
            chan.get_pty(term="dumb", width=200, height=50)
        # Run the script as the command itself (sshd runs it via the login shell's -c),
        # not piped into `bash -s` over stdin: the stdin-EOF handshake did not make the
        # remote shell exit against the UAT host, so recv never saw the channel close.
        chan.exec_command(script)
        # Poll, do not block: the deadline is enforced HERE. A blocking recv() does not
        # notice the channel finishing and can spin past its own timeout (seen live against
        # the UAT host). recv_ready()/exit_status_ready() + a wall clock is the proven shape.
        deadline = monotonic() + timeout
        next_report = monotonic() + PROGRESS_EVERY
        out = b""
        while True:
            if monotonic() > deadline:
                chan.close()  # closing the session ends the command on the host
                return {"ok": False, "output": _txt(out)[-20000:],
                        "error": f"still running after {timeout}s on {address} - stopped "
                                 f"(a command that never ends by itself, like ping without -c, runs until this limit)"}
            if progress and monotonic() >= next_report:
                next_report = monotonic() + PROGRESS_EVERY
                if progress(_txt(out)):  # the platform says Stop
                    chan.close()
                    return {"ok": False, "output": _txt(out)[-20000:],
                            "error": "stopped from the SOC platform"}
            if chan.recv_ready():
                chunk = chan.recv(8192)
                if not chunk:
                    break
                out += chunk
                if len(out) > 1_000_000:
                    out = out[-200_000:]  # keep the tail; a chatty command must not eat the box's memory
            elif chan.exit_status_ready():
                break
            else:
                time.sleep(0.05)
        while chan.recv_ready():
            out += chan.recv(8192)
        code = chan.recv_exit_status()
        text = _txt(out)
        return {"ok": code == 0, "exit_code": code, "output": text[-20000:], "error": ""}
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


def _sudo_ws(target: dict) -> bool:
    """Ubuntu 25.10+ makes sudo-rs the default `sudo` and keeps the original as `sudo.ws`.
    Ansible's become prompt handling times out against sudo-rs with a message that never
    mentions sudo (seen with the Engineer System worker), so use sudo.ws where it exists."""
    try:
        r = _ssh_run(target, "command -v sudo.ws >/dev/null 2>&1 && echo yes || echo no", 20)
    except Exception:  # noqa: BLE001 - no paramiko (update.sh installs it): plain sudo, not a failed run
        return False
    return bool(r.get("ok")) and r.get("output", "").strip().endswith("yes")


def _inventory(hosts: list) -> tuple[dict, list]:
    """An Ansible YAML inventory (written as JSON, which is valid YAML - no quoting to get
    wrong) with every host in the group `targets`. Returns it and the secrets in it, so they
    can be masked out of anything printed."""
    import re
    secrets, entries, used = [], {}, set()
    for h in hosts:
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", h.get("name") or h.get("address") or "host")
        while name in used:
            name += "_"
        used.add(name)
        pw = h.get("password") or ""
        if pw:
            secrets.append(pw)
        v = {"ansible_host": h.get("address"), "ansible_port": int(h.get("port") or 22),
             "ansible_user": h.get("username") or "", "ansible_password": pw}
        if h.get("transport") == "winrm":
            v.update(ansible_connection="winrm", ansible_winrm_transport="ntlm",
                     ansible_winrm_scheme="https" if int(h.get("port") or 5985) == 5986 else "http",
                     ansible_winrm_server_cert_validation="ignore")
        else:
            v.update(ansible_connection="ssh", ansible_become_password=pw)
            if _sudo_ws(h):
                v["ansible_become_exe"] = "sudo.ws"
        entries[name] = v
    return {"all": {"children": {"targets": {"hosts": entries}}}}, secrets


def _tree(root: int) -> list:
    """root and every process descended from it, from /proc (parents first)."""
    kids: dict = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                ppid = int(open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
            kids.setdefault(ppid, []).append(int(p))
    out, todo = [], [root]
    while todo:
        p = todo.pop(0)
        out.append(p)
        todo += kids.get(p, [])
    return out


def _alive(pid: int) -> bool:
    """Running, i.e. not gone and not a zombie waiting to be reaped."""
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def _ansible_run(job: dict, progress=None) -> dict:
    """Run an approved playbook against the job's hosts, from THIS box as the Ansible
    control node. Playbook and inventory (which holds the hosts' logins) live in a 0700
    temporary directory only root can read, for the length of the run, and are removed
    whatever happens. Output streams to the platform like a command's does."""
    import shutil
    import signal
    import subprocess
    import tempfile
    import threading
    params = job.get("params") or {}
    playbook = params.get("playbook") or ""
    hosts = job.get("inventory") or []
    timeout = int(params.get("timeout") or 900)
    exe = shutil.which("ansible-playbook")
    if not exe:
        return {"status": "failed", "result": {"error": "Ansible is not installed on the collector - run: sudo pscyber-collector update"}, "output": ""}
    if not playbook.strip() or not hosts:
        return {"status": "failed", "result": {"error": "no playbook or no hosts in the job"}, "output": ""}
    if any(h.get("transport") != "winrm" for h in hosts) and not shutil.which("sshpass"):
        return {"status": "failed", "result": {"error": "sshpass is not installed on the collector (Ansible needs it for password SSH) - run: sudo pscyber-collector update"}, "output": ""}
    tmp = tempfile.mkdtemp(prefix="pscyber-ansible-")  # 0700
    try:
        inv, secrets = _inventory(hosts)

        def private(name: str, text: str) -> str:
            p = os.path.join(tmp, name)
            with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(text)
            return p
        inv_p = private("inventory.json", json.dumps(inv))
        pb_p = private("playbook.yml", playbook)
        cfg_p = private("ansible.cfg", "[defaults]\nretry_files_enabled = False\nnocolor = True\n"
                                       "interpreter_python = auto_silent\n")
        env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "HOME": tmp, "LANG": "C.UTF-8",
               "ANSIBLE_CONFIG": cfg_p, "ANSIBLE_HOST_KEY_CHECKING": "False",
               "ANSIBLE_LOCAL_TEMP": os.path.join(tmp, "local"), "ANSIBLE_FORCE_COLOR": "0",
               "ANSIBLE_SSH_ARGS": "-o ControlMaster=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"}
        proc = subprocess.Popen([exe, "-i", inv_p, pb_p], cwd=tmp, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        chunks: list = []
        reader = threading.Thread(target=lambda: [chunks.append(b) for b in iter(lambda: proc.stdout.read1(8192), b"")], daemon=True)
        reader.start()

        def text() -> str:
            t = _txt(b"".join(chunks))
            for s in secrets:
                if len(s) >= 3:
                    t = t.replace(s, "********")  # a playbook that prints a login must not ship it
            return t[-20000:]

        def stop_all():
            # The whole TREE, not the process group: sshpass starts ssh in a session of its
            # own, so killpg left ssh - and the command on the host - running (seen on the UAT
            # box). Ending ssh (-tt) hangs the remote command up.
            pids = _tree(proc.pid)
            for sig in (signal.SIGTERM, signal.SIGKILL):
                for p in pids:
                    try:
                        os.kill(p, sig)
                    except OSError:
                        pass
                deadline_kill = monotonic() + 5
                while monotonic() < deadline_kill and any(os.path.exists(f"/proc/{p}") and _alive(p) for p in pids):
                    time.sleep(0.2)
            try:
                proc.wait(5)
            except Exception:  # noqa: BLE001
                pass
        deadline = monotonic() + timeout
        next_report = monotonic() + PROGRESS_EVERY
        while proc.poll() is None:
            if monotonic() > deadline:
                stop_all()
                return {"status": "failed", "result": {"error": f"playbook still running after {timeout}s - stopped"}, "output": text()}
            if progress and monotonic() >= next_report:
                next_report = monotonic() + PROGRESS_EVERY
                if progress(text()):
                    stop_all()
                    return {"status": "failed", "result": {"error": "stopped from the SOC platform"}, "output": text()}
            time.sleep(0.2)
        reader.join(5)
        code = proc.returncode
        # 2 = a host failed, 4 = a host unreachable (ansible-playbook's own exit codes)
        why = {0: "", 2: "a task failed on at least one host", 4: "at least one host was unreachable"}.get(code, f"exit code {code}")
        return {"status": "done" if code == 0 else "failed", "result": {"exit_code": code, "error": why}, "output": text()}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_job(job: dict, progress=None) -> dict:
    """Dispatch one claimed job to its executor. Returns {status, result, output}.
    progress(output_so_far) -> True means Stop was pressed (SSH commands and playbooks;
    a WinRM command returns its output at the end)."""
    action = job.get("action")
    if action == "ansible":
        return _ansible_run(job, progress)
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
        timeout = int((job.get("params") or {}).get("timeout") or 300)
        r = _ssh_run(target, script, timeout, progress) if transport == "ssh" else _winrm_run(target, script, timeout)
        # Many network CLIs report no exit status (-1) for a command that worked: there,
        # only a transport error is a failure.
        ok = r["ok"] or (network and not r.get("error"))
        return {"status": "done" if ok else "failed",
                "result": {"exit_code": r.get("exit_code"), "error": r.get("error", "")}, "output": r["output"]}
    return {"status": "failed", "result": {"error": f"unknown action '{action}'"}, "output": ""}


MAX_PARALLEL = 4  # jobs at once: a long command must not hold a Check up behind it


def _work(job: dict, cfg: dict, ctx: ssl.SSLContext) -> None:
    def progress(output: str) -> bool:
        try:
            return bool(_post(f"/api/collectors/jobs/{job['id']}/progress", {"output": output[-20000:]}, cfg, ctx).get("cancel"))
        except Exception:  # noqa: BLE001 - an older platform, or a blip: keep running
            return False
    try:
        res = run_job(job, progress)
    except Exception as e:  # noqa: BLE001 - one bad job must not kill the responder
        res = {"status": "failed", "result": {"error": f"{type(e).__name__}: {e}"}, "output": ""}
    for _ in range(3):  # the result is the only record of what happened - retry a blip
        try:
            _post(f"/api/collectors/jobs/{job['id']}/result", res, cfg, ctx)
            return
        except Exception:  # noqa: BLE001
            time.sleep(3)


def main() -> None:
    import threading
    ctx = _ctx()
    busy: set = set()
    lock = threading.Lock()

    def run(job, cfg):
        try:
            _work(job, cfg, ctx)
        finally:
            with lock:
                busy.discard(job["id"])

    while True:
        delay = POLL_IDLE
        try:
            cfg = _cfg()
            with lock:
                free = MAX_PARALLEL - len(busy)
            if free > 0:
                for job in _post("/api/collectors/jobs/claim", {"max": free}, cfg, ctx).get("jobs") or []:
                    delay = POLL_BUSY
                    with lock:
                        busy.add(job["id"])
                    threading.Thread(target=run, args=(job, cfg), daemon=True).start()
        except urllib.error.URLError:
            delay = POLL_IDLE  # platform unreachable; keep trying quietly
        except Exception:  # noqa: BLE001
            delay = POLL_IDLE
        time.sleep(delay)


if __name__ == "__main__":
    main()
