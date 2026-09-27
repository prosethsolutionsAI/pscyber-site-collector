#!/usr/bin/env bash
# PSCyber Site Collector - installer and setup wizard.
#
# One Linux box at the customer site. Switches/firewalls send syslog to it,
# devices send SNMP traps to it, and the site's Windows/Linux Wazuh agents point
# at it. It forwards everything to the Proseth SOC through a MUTUAL-TLS tunnel
# (it proves who it is with its own certificate; it checks the SOC's certificate
# against a pinned CA). Nothing inbound is needed at the customer's firewall -
# only outbound TCP to the SOC gateway.
#
#   curl -sk https://<platform>/collector/install.sh -o install.sh
#   sudo PSCYBER_PLATFORM='https://<platform>' PSCYBER_TOKEN='<token>' bash install.sh
#
# Run without the variables and it asks. Safe to run again (e.g. with a new
# token to move the collector to a new box). `pscyber-collector uninstall` removes it.
set -uo pipefail

# Not "VERSION": sourcing /etc/os-release below would overwrite it with the OS version.
COLLECTOR_VERSION="1.0.3"
WAZUH_AGENT_VERSION="4.14.7"
ETC=/etc/pscyber-collector
LOGDIR=/var/log/pscyber

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash install.sh"

# ------------------------------------------------------------------ wizard
PLATFORM="${PSCYBER_PLATFORM:-}"
TOKEN="${PSCYBER_TOKEN:-}"
COMMUNITY="${PSCYBER_SNMP_COMMUNITY:-}"
CA_FP_EXPECTED="${PSCYBER_CA_FINGERPRINT:-}"
INTERACTIVE=1; [ -n "$PLATFORM" ] && [ -n "$TOKEN" ] && INTERACTIVE=0

echo
echo "  PSCyber Site Collector $COLLECTOR_VERSION"
echo "  Forwards this site's syslog, SNMP traps and Wazuh agents to the Proseth SOC."
echo
[ -n "$PLATFORM" ] || read -r -p "  Platform URL (given by Proseth, e.g. https://soc.example.com:8443): " PLATFORM
[ -n "$TOKEN" ]    || read -r -p "  Install token (from the platform, Collectors page): " TOKEN
if [ -z "$COMMUNITY" ]; then
  if [ "$INTERACTIVE" = 1 ]; then read -r -p "  SNMP trap community the devices use [public]: " COMMUNITY; fi
  COMMUNITY="${COMMUNITY:-public}"
fi
PLATFORM="${PLATFORM%/}"
[ -n "$PLATFORM" ] && [ -n "$TOKEN" ] || die "platform URL and install token are required"

# ------------------------------------------------------------------ packages
. /etc/os-release
if command -v apt-get >/dev/null; then
  PKG=deb
  say "installing packages (apt)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || die "apt-get update failed"
  apt-get install -y -qq curl openssl python3 rsyslog stunnel4 snmptrapd snmp >/dev/null || die "package install failed"
elif command -v dnf >/dev/null || command -v yum >/dev/null; then
  PKG=rpm; PM=$(command -v dnf || command -v yum)
  say "installing packages ($PM)"
  "$PM" install -y -q curl openssl python3 rsyslog stunnel net-snmp net-snmp-utils >/dev/null || die "package install failed"
else
  die "unsupported OS ($PRETTY_NAME) - Debian/Ubuntu or RHEL/Rocky/Alma needed"
fi
STUNNEL=$(command -v stunnel || command -v stunnel4) || die "stunnel not found after install"
ok "packages on $PRETTY_NAME"

# ------------------------------------------------------------------ trust: pin the SOC's CA
mkdir -p "$ETC" && chmod 700 "$ETC"
say "fetching the SOC collector CA from $PLATFORM"
curl -sfk "$PLATFORM/api/collectors/ca" -o "$ETC/ca.pem" || die "cannot reach $PLATFORM (check the address and the outbound firewall)"
CA_FP=$(openssl x509 -in "$ETC/ca.pem" -noout -fingerprint -sha256 | cut -d= -f2)
echo "     CA fingerprint: $CA_FP"
if [ -n "$CA_FP_EXPECTED" ]; then
  [ "${CA_FP_EXPECTED^^}" = "$CA_FP" ] || die "CA fingerprint does NOT match the one given - stopping (possible interception)"
  ok "CA fingerprint matches the expected value"
elif [ "$INTERACTIVE" = 1 ]; then
  read -r -p "  Does it match the fingerprint shown in the platform? [y/N] " yn
  [[ "$yn" =~ ^[Yy] ]] || die "not confirmed - stopping"
else
  warn "no PSCYBER_CA_FINGERPRINT given - trusting the CA on first use"
fi
# The platform's own HTTPS certificate, pinned for the heartbeat.
host_port="${PLATFORM#https://}"; host_port="${host_port%%/*}"
echo | openssl s_client -connect "$host_port" -showcerts 2>/dev/null | openssl x509 > "$ETC/platform.pem" 2>/dev/null \
  || warn "could not save the platform certificate - heartbeat will not verify it"

# ------------------------------------------------------------------ enrol
say "enrolling with the platform"
[ -f "$ETC/client.key" ] || { openssl ecparam -name prime256v1 -genkey -noout -out "$ETC/client.key" && chmod 600 "$ETC/client.key"; }
openssl req -new -key "$ETC/client.key" -subj "/CN=$(hostname)" -out "$ETC/client.csr" 2>/dev/null || die "CSR failed"
REQ=$(python3 - "$TOKEN" "$ETC/client.csr" <<'PY'
import json, platform, socket, sys
print(json.dumps({"token": sys.argv[1], "csr": open(sys.argv[2]).read(), "hostname": socket.gethostname(),
                  "facts": {"os": platform.platform(), "python": platform.python_version()}}))
PY
)
RESP=$(curl -sk -X POST -H 'Content-Type: application/json' --data "$REQ" "$PLATFORM/api/collectors/enroll" -w '\n%{http_code}')
CODE=$(echo "$RESP" | tail -n1); BODY=$(echo "$RESP" | sed '$d')
[ "$CODE" = "200" ] || die "enrolment refused (HTTP $CODE): $BODY"
echo "$BODY" | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
etc = "/etc/pscyber-collector"
open(f"{etc}/client.crt", "w").write(d["client_cert"])
ca_new = d["ca_cert"].strip()
if ca_new != open(f"{etc}/ca.pem").read().strip():
    sys.exit("the CA returned at enrolment differs from the one fetched first - stopping")
key = d.pop("agent_key")
with open(f"{etc}/agent.key", "w") as f:
    f.write(key)
os.chmod(f"{etc}/agent.key", 0o600)
d.pop("client_cert"); d.pop("ca_cert")
with open(f"{etc}/config.json", "w") as f:
    json.dump(d, f, indent=1)
os.chmod(f"{etc}/config.json", 0o600)
' || die "could not store the enrolment result"
echo "$PLATFORM" > "$ETC/platform_url"
cfg() { python3 -c "import json;print(json.load(open('$ETC/config.json'))['$1'])"; }
GW_HOST=$(cfg gateway_host); GW_EV=$(cfg gateway_events_port); GW_EN=$(cfg gateway_enroll_port)
TENANT=$(cfg tenant_name); AGENT_NAME=$(cfg agent_name)
ok "enrolled for customer '$TENANT' as $AGENT_NAME"

# ------------------------------------------------------------------ mutual-TLS tunnel
say "configuring the TLS tunnel to $GW_HOST"
if [[ "$GW_HOST" =~ ^[0-9.]+$ ]]; then CHECK="checkIP = $GW_HOST"; else CHECK="checkHost = $GW_HOST"; fi
cat > "$ETC/stunnel.conf" <<EOF
; PSCyber collector -> SOC gateway. Mutual TLS: this box presents client.crt,
; and accepts the gateway only if its certificate chains to the pinned CA.
foreground = yes
pid =
[wazuh-events]
client = yes
accept = 0.0.0.0:1514
connect = $GW_HOST:$GW_EV
cert = $ETC/client.crt
key = $ETC/client.key
CAfile = $ETC/ca.pem
verifyChain = yes
$CHECK
sslVersionMin = TLSv1.2
[wazuh-enroll]
client = yes
accept = 0.0.0.0:1515
connect = $GW_HOST:$GW_EN
cert = $ETC/client.crt
key = $ETC/client.key
CAfile = $ETC/ca.pem
verifyChain = yes
$CHECK
sslVersionMin = TLSv1.2
EOF
cat > /etc/systemd/system/pscyber-tunnel.service <<EOF
[Unit]
Description=PSCyber collector TLS tunnel to the SOC
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$STUNNEL $ETC/stunnel.conf
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------------------------ syslog + SNMP traps
say "configuring syslog (UDP/TCP 514) and SNMP traps (UDP 162)"
SYSLOG_USER=root; id syslog >/dev/null 2>&1 && SYSLOG_USER=syslog
mkdir -p "$LOGDIR/syslog"; chown -R "$SYSLOG_USER":root "$LOGDIR"; chmod 750 "$LOGDIR" "$LOGDIR/syslog"
cat > /etc/rsyslog.d/30-pscyber-collector.conf <<'EOF'
# PSCyber collector: remote devices -> one file per sending device, in standard
# syslog form with the DEVICE's address as the host (Wazuh reads these files).
module(load="imudp")
module(load="imtcp")
template(name="PscyberLine" type="string" string="%timereported:::date-rfc3164% %fromhost-ip% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
template(name="PscyberFile" type="string" string="/var/log/pscyber/syslog/%fromhost-ip%.log")
ruleset(name="pscyber_remote") {
  action(type="omfile" dynaFile="PscyberFile" template="PscyberLine" fileCreateMode="0640")
  stop
}
input(type="imudp" port="514" ruleset="pscyber_remote")
input(type="imtcp" port="514" ruleset="pscyber_remote")
# SNMP traps arrive from snmptrapd on facility local5
local5.* action(type="omfile" file="/var/log/pscyber/snmptraps.log" template="RSYSLOG_TraditionalFileFormat" fileCreateMode="0640")
& stop
EOF
mkdir -p /etc/snmp
cat > /etc/snmp/snmptrapd.conf <<EOF
# PSCyber collector - accept traps from devices using this community, log them.
authCommunity log $COMMUNITY
format2 TRAP from %B [%b]: %v\n
EOF
mkdir -p /etc/systemd/system/snmptrapd.service.d
# Log traps to syslog facility local5 (rsyslog writes them for Wazuh). No -p pidfile:
# on Ubuntu 26.04 the unit runs unprivileged and cannot write one ("fopen: Permission
# denied"); keep the listen addresses the distribution's unit uses.
cat > /etc/systemd/system/snmptrapd.service.d/pscyber.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/snmptrapd -Ls5 -f udp:162 udp6:162
EOF

# ------------------------------------------------------------------ Wazuh agent (through the tunnel)
say "installing the Wazuh agent $WAZUH_AGENT_VERSION (connects through the tunnel)"
systemctl stop wazuh-agent 2>/dev/null || true
if ! /var/ossec/bin/wazuh-control info 2>/dev/null | grep -q "v$WAZUH_AGENT_VERSION"; then
  cd /tmp
  if [ "$PKG" = deb ]; then
    curl -sfo wazuh-agent.deb "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_AGENT_VERSION}-1_amd64.deb" || die "agent download failed"
    WAZUH_MANAGER=127.0.0.1 dpkg -i ./wazuh-agent.deb >/tmp/pscyber-agent-install.log 2>&1 || die "agent install failed (see /tmp/pscyber-agent-install.log)"
    rm -f wazuh-agent.deb
  else
    curl -sfo wazuh-agent.rpm "https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_AGENT_VERSION}-1.x86_64.rpm" || die "agent download failed"
    WAZUH_MANAGER=127.0.0.1 rpm -Uvh --force wazuh-agent.rpm >/tmp/pscyber-agent-install.log 2>&1 || die "agent install failed"
    rm -f wazuh-agent.rpm
  fi
fi
OSSEC=/var/ossec/etc/ossec.conf
python3 - "$OSSEC" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p).read()
t = re.sub(r"<address>[^<]*</address>", "<address>127.0.0.1</address>", t, count=1)
# The key is imported from the platform - this agent must never try to self-enrol.
t = re.sub(r"<enrollment>.*?</enrollment>", "", t, flags=re.S)
t = re.sub(r"<!-- PSCYBER-COLLECTOR -->.*?<!-- /PSCYBER-COLLECTOR -->\s*", "", t, flags=re.S)
block = """<!-- PSCYBER-COLLECTOR -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/pscyber/syslog/*.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/pscyber/snmptraps.log</location>
  </localfile>
</ossec_config>
<!-- /PSCYBER-COLLECTOR -->
"""
open(p, "w").write(t.rstrip() + "\n" + block)
PY
: > /var/ossec/etc/client.keys
/var/ossec/bin/manage_agents -i "$(cat "$ETC/agent.key")" <<<'y' >/dev/null || die "could not import the agent key"
ok "agent key imported ($AGENT_NAME)"

# ------------------------------------------------------------------ heartbeat + CLI
say "installing the heartbeat and the pscyber-collector command"
mkdir -p /opt/pscyber-collector
curl -sfk "$PLATFORM/collector/files/heartbeat.py" -o /opt/pscyber-collector/heartbeat.py || die "cannot fetch heartbeat.py"
echo "$COLLECTOR_VERSION" > /opt/pscyber-collector/VERSION
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
cat > /usr/local/bin/pscyber-collector <<'EOF'
#!/usr/bin/env bash
# PSCyber collector: status | site-agent-command | uninstall
case "${1:-status}" in
  status)
    for s in pscyber-tunnel wazuh-agent rsyslog snmptrapd pscyber-heartbeat.timer; do
      printf '%-24s %s\n' "$s" "$(systemctl is-active "$s")"; done
    grep -h "^status=" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | sed 's/^/wazuh agent /'
    echo "syslog sources: $(ls /var/log/pscyber/syslog 2>/dev/null | wc -l)"
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
    systemctl disable --now pscyber-tunnel pscyber-heartbeat.timer 2>/dev/null
    systemctl stop wazuh-agent 2>/dev/null
    rm -f /etc/systemd/system/pscyber-tunnel.service /etc/systemd/system/pscyber-heartbeat.{service,timer}
    rm -rf /etc/systemd/system/snmptrapd.service.d/pscyber.conf /etc/rsyslog.d/30-pscyber-collector.conf
    systemctl daemon-reload; systemctl restart rsyslog 2>/dev/null; systemctl restart snmptrapd 2>/dev/null
    if command -v apt-get >/dev/null; then apt-get purge -y -qq wazuh-agent >/dev/null; else (dnf -y remove wazuh-agent || yum -y remove wazuh-agent) >/dev/null; fi
    rm -rf /var/ossec /etc/pscyber-collector /opt/pscyber-collector /var/log/pscyber /usr/local/bin/pscyber-collector
    if command -v ufw >/dev/null; then
      for r in 514/udp 514/tcp 162/udp 1514/tcp 1515/tcp; do ufw delete allow "$r" >/dev/null 2>&1; done
    fi
    echo "PSCyber collector removed. Ask the SOC to revoke it in the platform (Collectors page)."
    ;;
  *) echo "usage: pscyber-collector [status|site-agent-command|uninstall]"; exit 2 ;;
esac
EOF
chmod 755 /usr/local/bin/pscyber-collector

# ------------------------------------------------------------------ start
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  say "opening the collector ports in ufw (site devices -> this box)"
  for r in 514/udp 514/tcp 162/udp 1514/tcp 1515/tcp; do ufw allow "$r" comment "PSCyber collector" >/dev/null; done
fi
systemctl daemon-reload
systemctl enable --now pscyber-tunnel >/dev/null 2>&1 || die "tunnel failed to start (journalctl -u pscyber-tunnel)"
systemctl restart rsyslog || die "rsyslog failed (journalctl -u rsyslog)"
systemctl enable snmptrapd >/dev/null 2>&1; systemctl restart snmptrapd || warn "snmptrapd did not start"
systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent || die "wazuh-agent failed to start"
systemctl enable --now pscyber-heartbeat.timer >/dev/null 2>&1
sleep 15
python3 /opt/pscyber-collector/heartbeat.py >/dev/null 2>&1 || warn "first heartbeat failed - the platform will show it offline until one succeeds"

echo
ok "PSCyber Site Collector $COLLECTOR_VERSION installed for '$TENANT'"
echo "     Point switches/firewalls syslog at:   $(hostname -I | awk '{print $1}') UDP/TCP 514"
echo "     Point SNMP traps at:                  $(hostname -I | awk '{print $1}') UDP 162 (community '$COMMUNITY')"
echo "     Site Wazuh agents:                    pscyber-collector site-agent-command"
echo "     Health:                               pscyber-collector status"
