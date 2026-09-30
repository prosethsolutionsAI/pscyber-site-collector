#!/usr/bin/env bash
# PSCyber Site Collector - update (and the software half of the install).
#
# Refreshes the collector's own software from the platform it is enrolled with:
# the heartbeat, the responder (site worker), the pscyber-collector command and
# the self-update helper. It never touches the enrolment, the certificates, the
# tunnel or the Wazuh agent, so it is safe to run at any time, as often as you like.
#
# A collector older than 1.1.1 has to be updated by hand ONCE:
#   curl -sk https://<platform>/collector/update.sh -o update.sh && sudo bash update.sh
# From 1.1.1 on: the Update button on the platform's Collectors page, or
#   sudo pscyber-collector update
set -uo pipefail

ETC=/etc/pscyber-collector
OPT=/opt/pscyber-collector

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash update.sh"
[ -f "$ETC/config.json" ] || die "this box is not an enrolled collector - run install.sh first"

# Two updates at once would race over the same files and services.
exec 9>/run/pscyber-collector-update.lock
flock -n 9 || die "another update is already running on this box"

PLATFORM="${PSCYBER_PLATFORM:-$(cat "$ETC/platform_url" 2>/dev/null)}"
PLATFORM="${PLATFORM%/}"
[ -n "$PLATFORM" ] || die "no platform address in $ETC/platform_url"

# Fetch from the platform PINNED to the certificate saved at install: this code
# runs as root, so it must come from the platform this box enrolled with and
# nowhere else. (-k only drops the name check - a public collector reaches the
# platform through a NAT address that is not in its certificate; the pin is the check.)
CURL=(curl -sf --max-time 60 -k)
if [ -s "$ETC/platform.pem" ]; then
  PIN=$(openssl x509 -in "$ETC/platform.pem" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | base64)
  if [ -n "$PIN" ]; then CURL+=(--pinnedpubkey "sha256//$PIN"); else warn "could not read the pinned certificate - fetching unpinned"; fi
else
  warn "no pinned platform certificate on this box - fetching unpinned"
fi

say "fetching the collector software from $PLATFORM"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
for f in heartbeat.py responder.py VERSION; do
  "${CURL[@]}" "$PLATFORM/collector/files/$f" -o "$STAGE/$f" \
    || die "cannot fetch $f (platform unreachable, or its certificate no longer matches the one pinned at install)"
  [ -s "$STAGE/$f" ] || die "$f came back empty - nothing changed"
done
python3 -m py_compile "$STAGE/heartbeat.py" "$STAGE/responder.py" 2>/dev/null \
  || die "the downloaded code does not compile - nothing changed"
NEW=$(tr -d '[:space:]' < "$STAGE/VERSION")
OLD=$(tr -d '[:space:]' < "$OPT/VERSION" 2>/dev/null || true)
ok "fetched ${NEW} (this box had ${OLD:-nothing})"

# ------------------------------------------------------------------ libraries
# paramiko reaches Linux hosts and network devices over SSH; pywinrm reaches
# Windows hosts (and domain controllers) over WinRM.
need=()
python3 -c 'import paramiko' 2>/dev/null || need+=(paramiko)
python3 -c 'import winrm' 2>/dev/null || need+=(winrm)
if [ ${#need[@]} -gt 0 ]; then
  say "installing Python libraries: ${need[*]}"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    pkgs=(); for n in "${need[@]}"; do pkgs+=("python3-$n"); done
    apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1; }
  else
    PM=$(command -v dnf || command -v yum)
    [[ " ${need[*]} " == *" paramiko "* ]] && "$PM" -y -q install python3-paramiko >/dev/null 2>&1
    if [[ " ${need[*]} " == *" winrm "* ]]; then
      "$PM" -y -q install python3-pip >/dev/null 2>&1
      pip3 install -q pywinrm >/dev/null 2>&1
    fi
  fi
  python3 -c 'import paramiko' 2>/dev/null || warn "paramiko is missing - SSH hosts (Linux, network devices) cannot be reached"
  python3 -c 'import winrm' 2>/dev/null || warn "pywinrm is missing - Windows hosts cannot be reached"
fi

# ------------------------------------------------------------------ software
mkdir -p "$OPT" /var/log/pscyber
for f in heartbeat.py responder.py VERSION; do
  install -m 644 "$STAGE/$f" "$OPT/$f.new" && mv -f "$OPT/$f.new" "$OPT/$f" || die "could not install $f"
done

# The self-update helper: what the Update button runs. Root-owned, takes no
# arguments, and fetches update.sh itself - pinned - so nothing can be passed in.
cat > /usr/local/sbin/pscyber-collector-update <<'EOF'
#!/usr/bin/env bash
# PSCyber collector self-update: fetch update.sh from the enrolled platform (pinned) and run it.
set -uo pipefail
ETC=/etc/pscyber-collector
PLATFORM=$(cat "$ETC/platform_url"); PLATFORM="${PLATFORM%/}"
CURL=(curl -sf --max-time 60 -k)
if [ -s "$ETC/platform.pem" ]; then
  PIN=$(openssl x509 -in "$ETC/platform.pem" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | base64)
  [ -n "$PIN" ] && CURL+=(--pinnedpubkey "sha256//$PIN")
fi
T=$(mktemp); trap 'rm -f "$T"' EXIT
"${CURL[@]}" "$PLATFORM/collector/update.sh" -o "$T" || { echo "cannot fetch update.sh from $PLATFORM" >&2; exit 1; }
bash "$T"
EOF
chmod 755 /usr/local/sbin/pscyber-collector-update

# ------------------------------------------------------------------ services
cat > /etc/systemd/system/pscyber-heartbeat.service <<'EOF'
[Unit]
Description=PSCyber collector heartbeat to the SOC platform
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/pscyber-collector/heartbeat.py
EOF
cat > /etc/systemd/system/pscyber-heartbeat.timer <<'EOF'
[Unit]
Description=PSCyber collector heartbeat every minute
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/pscyber-responder.service <<'EOF'
[Unit]
Description=PSCyber collector responder (site worker)
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/pscyber-collector/responder.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/pscyber-collector <<'EOF'
#!/usr/bin/env bash
# PSCyber collector: status | update | site-agent-command | uninstall
case "${1:-status}" in
  status)
    echo "version                  $(cat /opt/pscyber-collector/VERSION 2>/dev/null)"
    for s in pscyber-tunnel wazuh-agent rsyslog snmptrapd pscyber-heartbeat.timer pscyber-responder; do
      printf '%-24s %s\n' "$s" "$(systemctl is-active "$s")"; done
    grep -h "^status=" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | sed 's/^/wazuh agent /'
    echo "syslog sources: $(ls /var/log/pscyber/syslog 2>/dev/null | wc -l)"
    ;;
  update)
    [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo pscyber-collector update"; exit 1; }
    /usr/local/sbin/pscyber-collector-update
    ;;
  site-agent-command)
    ip=$(hostname -I | awk '{print $1}')
    pw=$(python3 -c "import json;print(json.load(open('/etc/pscyber-collector/config.json')).get('site_agent_enroll_password',''))")
    grp=$(python3 -c "import json;print(json.load(open('/etc/pscyber-collector/config.json'))['group'])")
    extra=""; [ -n "$pw" ] && extra=" WAZUH_REGISTRATION_PASSWORD='$pw'"
    echo "Linux (deb):  sudo WAZUH_MANAGER='$ip'$extra WAZUH_AGENT_GROUP='$grp' dpkg -i ./wazuh-agent_4.14.7-1_amd64.deb"
    echo "Windows:      msiexec.exe /i wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER='$ip'$extra WAZUH_AGENT_GROUP='$grp'"
    [ -z "$pw" ] && echo "(no enrolment password was provided by the platform - agents will be refused until ENROLL_PASSWORD is set there)"
    ;;
  uninstall)
    systemctl disable --now pscyber-tunnel pscyber-heartbeat.timer pscyber-responder 2>/dev/null
    systemctl stop wazuh-agent 2>/dev/null
    rm -f /etc/systemd/system/pscyber-tunnel.service /etc/systemd/system/pscyber-heartbeat.{service,timer} /etc/systemd/system/pscyber-responder.service
    rm -rf /etc/systemd/system/snmptrapd.service.d/pscyber.conf /etc/rsyslog.d/30-pscyber-collector.conf
    systemctl daemon-reload; systemctl restart rsyslog 2>/dev/null; systemctl restart snmptrapd 2>/dev/null
    if command -v apt-get >/dev/null; then apt-get purge -y -qq wazuh-agent >/dev/null; else (dnf -y remove wazuh-agent || yum -y remove wazuh-agent) >/dev/null; fi
    rm -rf /var/ossec /etc/pscyber-collector /opt/pscyber-collector /var/log/pscyber /usr/local/bin/pscyber-collector /usr/local/sbin/pscyber-collector-update
    if command -v ufw >/dev/null; then
      for r in 514/udp 514/tcp 162/udp 1514/tcp 1515/tcp; do ufw delete allow "$r" >/dev/null 2>&1; done
    fi
    echo "PSCyber collector removed. Ask the SOC to revoke it in the platform (Collectors page)."
    ;;
  *) echo "usage: pscyber-collector [status|update|site-agent-command|uninstall]"; exit 2 ;;
esac
EOF
chmod 755 /usr/local/bin/pscyber-collector

systemctl daemon-reload
systemctl enable --now pscyber-heartbeat.timer >/dev/null 2>&1 || warn "heartbeat timer did not start (journalctl -u pscyber-heartbeat)"
systemctl enable pscyber-responder >/dev/null 2>&1
systemctl restart pscyber-responder || warn "responder did not start (journalctl -u pscyber-responder)"

# Report the new version straight away, so the platform stops showing the update as pending.
python3 "$OPT/heartbeat.py" >/dev/null 2>&1 || warn "heartbeat failed - the platform will show the new version at the next successful one"
ok "PSCyber Site Collector is now $NEW"
