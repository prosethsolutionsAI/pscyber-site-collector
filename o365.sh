#!/usr/bin/env bash
# PSCyber Site Collector - Microsoft 365 audit logs.
#
# Microsoft 365 cannot SEND logs anywhere. The Wazuh agent on this collector
# PULLS them, every minute, from Microsoft's Office 365 Management Activity API
# (outbound HTTPS 443 only), and they travel to the SOC through the collector's
# tunnel like everything else - labelled as this customer.
#
#   sudo PSCYBER_O365_TENANT=<tenant id> PSCYBER_O365_CLIENT=<client id> bash o365.sh
#   sudo PSCYBER_O365_REMOVE=1 bash o365.sh        # stop collecting, remove the secret
#
# Optional: PSCYBER_O365_SUBS (comma list, default: all five)
#           PSCYBER_O365_API_TYPE (commercial | gcc | gcc-high, default commercial)
#
# The client secret is ASKED for (typing hidden) and kept only on this machine,
# in a file only Wazuh can read: never on a command line, never in the platform.
# Everything is tested against Microsoft BEFORE the agent is touched, and the
# previous agent configuration is put back if the agent does not come up.
set -uo pipefail

TENANT="${PSCYBER_O365_TENANT:-}"
CLIENT="${PSCYBER_O365_CLIENT:-}"
SUBS="${PSCYBER_O365_SUBS:-Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General,DLP.All}"
API_TYPE="${PSCYBER_O365_API_TYPE:-commercial}"
REMOVE="${PSCYBER_O365_REMOVE:-0}"

OSSEC=/var/ossec
CONF="$OSSEC/etc/ossec.conf"
SECRET_FILE="$OSSEC/etc/pscyber-o365.secret"
BACKUP="$CONF.pscyber-o365.bak"
MARK_BEGIN="PSCYBER-O365 BEGIN"
MARK_END="PSCYBER-O365 END"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: sudo ... bash o365.sh"
[ -f "$CONF" ] || die "no Wazuh agent here ($CONF missing) - run this on the customer's site collector"
command -v python3 >/dev/null || die "python3 is needed (the collector installer puts it there)"
[ -d /etc/pscyber-collector ] || warn "this does not look like a PSCyber site collector - the logs will be labelled with whichever customer this agent belongs to"
WAZUH_GROUP=wazuh; getent group wazuh >/dev/null || WAZUH_GROUP=ossec

strip_block() {  # remove our block from ossec.conf - safe to run when it is not there
  python3 - "$CONF" "$MARK_BEGIN" "$MARK_END" <<'PY'
import sys
path, begin, end = sys.argv[1:4]
lines, out, skip = open(path).read().split("\n"), [], False
for line in lines:
    if begin in line:
        skip = True
        continue
    if skip and end in line:
        skip = False
        continue
    if not skip:
        out.append(line)
# The block was appended after a blank line: drop the trailing blank lines it
# leaves, so a remove gives back the file exactly as it was (tested byte for byte).
open(path, "w").write("\n".join(out).rstrip("\n") + "\n")
PY
}

restart_or_restore() {
  systemctl restart wazuh-agent
  sleep 5
  if ! systemctl is-active --quiet wazuh-agent; then
    warn "the Wazuh agent did not start with the new configuration - putting the previous one back"
    cp -p "$BACKUP" "$CONF"
    systemctl restart wazuh-agent
    die "configuration refused by the agent; nothing changed. Last agent log lines:
$(tail -n 15 "$OSSEC/logs/ossec.log" 2>/dev/null)"
  fi
}

# ------------------------------------------------------------------ remove
if [ "$REMOVE" = 1 ]; then
  say "stopping Microsoft 365 log collection"
  cp -p "$CONF" "$BACKUP"
  strip_block
  rm -f "$SECRET_FILE"
  restart_or_restore
  ok "removed - the agent no longer pulls Microsoft 365 logs, and the secret is deleted"
  echo "    (also delete the client secret in Entra ID -> App registrations, if nothing else uses it)"
  exit 0
fi

# ------------------------------------------------------------------ inputs
GUID='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
[[ "$TENANT" =~ $GUID ]] || die "PSCYBER_O365_TENANT must be the customer's Directory (tenant) ID - a GUID like 1b2c3d4e-..."
[[ "$CLIENT" =~ $GUID ]] || die "PSCYBER_O365_CLIENT must be the app's Application (client) ID - a GUID"
case "$API_TYPE" in
  commercial) LOGIN=login.microsoftonline.com; MANAGE=manage.office.com ;;
  gcc)        LOGIN=login.microsoftonline.com; MANAGE=manage-gcc.office.com ;;
  gcc-high)   LOGIN=login.microsoftonline.us;  MANAGE=manage.office365.us ;;
  *) die "PSCYBER_O365_API_TYPE must be commercial, gcc or gcc-high" ;;
esac
SUB_XML=""
IFS=',' read -r -a SUB_LIST <<< "$SUBS"
for s in "${SUB_LIST[@]}"; do
  s="${s// /}"
  case "$s" in
    Audit.AzureActiveDirectory|Audit.Exchange|Audit.SharePoint|Audit.General|DLP.All)
      SUB_XML+="      <subscription>$s</subscription>"$'\n' ;;
    "") ;;
    *) die "unknown log type '$s' - use Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All" ;;
  esac
done
[ -n "$SUB_XML" ] || die "choose at least one log type (PSCYBER_O365_SUBS)"

echo
echo "  Customer tenant : $TENANT"
echo "  App (client) ID : $CLIENT"
echo "  Log types       : $SUBS"
read -r -s -p "  Client secret (the VALUE, not the secret ID - typing is hidden): " SECRET </dev/tty
echo
[ -n "$SECRET" ] || die "no client secret given"

WORK=$(mktemp -d) || die "mktemp failed"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ test against Microsoft first
say "checking this collector can reach Microsoft (outbound HTTPS 443)"
for h in "$LOGIN" "$MANAGE"; do
  curl -s -o /dev/null --max-time 15 "https://$h/" && ok "$h reachable" \
    || die "cannot reach https://$h - allow the collector OUTBOUND TCP 443 to $LOGIN and $MANAGE"
done

say "signing in to Microsoft with the app (tests the IDs and the secret)"
printf '%s' "$SECRET" | curl -s --max-time 30 -o "$WORK/token.json" -X POST "https://$LOGIN/$TENANT/oauth2/v2.0/token" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=https://$MANAGE/.default" --data-urlencode "client_secret@-" \
  || die "the sign-in request failed - check the outbound firewall"
python3 - "$WORK/token.json" "$WORK/auth.hdr" <<'PY' || exit 1
import json, os, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit("\n\033[31mERROR:\033[0m Microsoft returned something unexpected - try again")
if "access_token" not in d:
    msg = (d.get("error_description") or d.get("error") or "unknown").split("\r\n")[0].split(" Trace ID")[0]
    hint = ""
    if "AADSTS7000215" in msg: hint = " -> the secret is wrong: paste the secret VALUE (shown once when it was created), not its ID"
    elif "AADSTS700016" in msg: hint = " -> no app with this client ID in this tenant: check both IDs"
    elif "AADSTS90002" in msg: hint = " -> no such tenant: check the Directory (tenant) ID"
    elif "AADSTS7000222" in msg: hint = " -> the secret has EXPIRED: create a new one in Entra ID"
    sys.exit(f"\n\033[31mERROR:\033[0m Microsoft refused the sign-in: {msg}{hint}")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, f"Authorization: Bearer {d['access_token']}\n".encode())
os.close(fd)
PY
rm -f "$WORK/token.json"
ok "signed in"

say "checking the app may read the audit logs (ActivityFeed.Read + admin consent)"
CODE=$(curl -s --max-time 30 -o "$WORK/subs.json" -w '%{http_code}' -H @"$WORK/auth.hdr" \
  "https://$MANAGE/api/v1.0/$TENANT/activity/feed/subscriptions/list")
case "$CODE" in
  200) ok "permission granted" ;;
  401|403) die "Microsoft says the app may not read audit logs (HTTP $CODE). In Entra ID -> App registrations -> this app -> API permissions:
       add 'Office 365 Management APIs' -> Application -> ActivityFeed.Read (and ActivityFeed.ReadDlp for DLP),
       then press 'Grant admin consent'. Wait a few minutes and run this again." ;;
  *) die "unexpected answer from Microsoft (HTTP $CODE): $(head -c 400 "$WORK/subs.json")
       If it mentions auditing: turn on audit logging in Microsoft Purview -> Audit, then run this again." ;;
esac

# ------------------------------------------------------------------ configure the agent
say "configuring the Wazuh agent"
cp -p "$CONF" "$BACKUP" || die "cannot back up $CONF"
( umask 027; printf '%s' "$SECRET" > "$SECRET_FILE" ) || die "cannot write $SECRET_FILE"
unset SECRET
chown "root:$WAZUH_GROUP" "$SECRET_FILE" && chmod 640 "$SECRET_FILE"
ok "secret stored in $SECRET_FILE (root and Wazuh only)"

strip_block
cat >> "$CONF" <<EOF

<!-- $MARK_BEGIN - written by the PSCyber o365.sh; run it again to change, PSCYBER_O365_REMOVE=1 to remove -->
<ossec_config>
  <office365>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <curl_max_size>1M</curl_max_size>
    <only_future_events>yes</only_future_events>
    <api_auth>
      <tenant_id>$TENANT</tenant_id>
      <client_id>$CLIENT</client_id>
      <client_secret_path>$SECRET_FILE</client_secret_path>
      <api_type>$API_TYPE</api_type>
    </api_auth>
    <subscriptions>
$SUB_XML    </subscriptions>
  </office365>
</ossec_config>
<!-- $MARK_END -->
EOF
restart_or_restore
ok "Wazuh agent restarted with Microsoft 365 collection"

sleep 10
ERRS=$(tail -n 300 "$OSSEC/logs/ossec.log" 2>/dev/null | grep -i 'office365' | grep -iE 'error|warn' | tail -n 5)
if [ -n "$ERRS" ]; then
  warn "the agent reported problems with Office 365:"
  echo "$ERRS" | sed 's/^/      /'
else
  ok "no Office 365 errors in the agent log"
fi

say "done"
echo "    The first events arrive within about 15 minutes (Microsoft publishes audit logs with a delay)."
echo "    They show up in the platform: Customers -> this customer -> Onboarding -> Microsoft 365 logs."
echo "    Only NEW activity is collected from now on - nothing older is pulled."
