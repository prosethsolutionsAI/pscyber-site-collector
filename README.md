# PSCyber Site Collector

One Linux box at a customer site that collects the site's security logs and
sends them to the **Proseth SOC** (Wazuh + Proseth SOC Agentic AI):

| From the site | Sent to | Port on the collector |
|---|---|---|
| Switches, routers, firewalls, anything that speaks **syslog** | the collector | **UDP/TCP 514** |
| Devices sending **SNMP traps** | the collector | **UDP 162** |
| **Wazuh agents** on the site's Windows / Linux servers and VMs | the collector (it relays them) | **TCP 1514, 1515** |

The collector forwards everything to the SOC through **one outbound, mutual-TLS
tunnel**. Nothing inbound has to be opened on the customer's firewall.

```
 switches / firewalls ──syslog 514──┐
 devices ─────────SNMP traps 162────┤                          ┌──────────── Proseth SOC ────────────┐
 Windows / Linux agents ─1514/1515──┤  PSCyber Site Collector  │                                     │
                                    └─►  rsyslog · snmptrapd ──┼─► gateway ─► Wazuh ─► Agentic AI    │
                                         Wazuh agent · stunnel │   (mTLS)                           │
                                         ═════ mutual TLS ═════┘                                     │
                                                                └─────────────────────────────────────┘
```

## Requirements

- A Linux VM or small server: **Ubuntu 22.04+ / Debian 12+** or **RHEL / Rocky / Alma 8+**,
  2 vCPU, 2 GB RAM, 20 GB disk is plenty for most sites.
- Outbound from the collector: **HTTPS to the SOC platform**, and **TCP 51514 and 51515
  to the SOC gateway** (Proseth gives you both addresses).
- An **install command** from Proseth (it contains a one-time token, valid 24 hours).

## Install

Proseth creates the collector in the SOC platform (*Site collectors → New collector*)
and sends you a command like:

```bash
curl -sk https://<soc-platform>/collector/install.sh -o install.sh
sudo PSCYBER_PLATFORM='https://<soc-platform>' PSCYBER_CA_FINGERPRINT='<fingerprint>' \
     PSCYBER_TOKEN='<one-time token>' bash install.sh
```

You can also take the installer from this repository:

```bash
curl -sO https://raw.githubusercontent.com/prosethsolutionsAI/pscyber-site-collector/main/install.sh
sudo bash install.sh          # the wizard asks for the platform URL and the token
```

The installer:

1. installs `rsyslog`, `snmptrapd`, `stunnel` and the **Wazuh agent 4.14.7**;
2. **pins the SOC's CA** - it shows the SHA-256 fingerprint and stops if it does not
   match the one Proseth gave you (`PSCYBER_CA_FINGERPRINT`);
3. creates this box's **own private key** (it never leaves the box) and enrols with the
   token: the SOC signs its certificate and registers it for **your company only**;
4. starts the TLS tunnel, syslog on 514, SNMP traps on 162, and a heartbeat so the SOC
   sees the collector's health every minute.

## After installing

```bash
pscyber-collector status               # tunnel, agent, syslog, traps, heartbeat
pscyber-collector site-agent-command   # the command to put Windows/Linux agents on this collector
```

- **Syslog**: point devices at the collector's IP, **UDP or TCP 514**. Each device's
  logs land in `/var/log/pscyber/syslog/<device-ip>.log` and are shipped to the SOC.
- **SNMP traps**: point devices at the collector's IP, **UDP 162**, with the community
  you gave the wizard (default `public` - change it on the devices and re-run the installer).
- **Site Wazuh agents**: install them with `WAZUH_MANAGER=<collector IP>` (the command
  above prints the exact line) - they reach the SOC through the collector.

## Security

- **Mutual TLS**: the collector proves who it is with a certificate the SOC signed for
  it; it accepts the SOC only if its certificate chains to the pinned CA. A collector
  that is lost or retired is **revoked** in the SOC and can no longer connect.
- The **install token works once** and expires after 24 hours.
- The Wazuh agent traffic inside the tunnel is additionally encrypted by Wazuh itself.
- The heartbeat sends only health (service states, how many devices send syslog,
  file sizes) - never log contents.
- Nothing in this repository is specific to any customer; everything site-specific is
  delivered at enrolment.

## Microsoft 365 audit logs (optional)

Microsoft 365 cannot send logs. With `o365.sh`, the Wazuh agent on this collector
**fetches** the customer's Office 365 audit logs from Microsoft every minute
(outbound HTTPS 443 to `login.microsoftonline.com` and `manage.office.com`) and sends
them through the same tunnel. Proseth gives you the exact command with your IDs:

```bash
curl -sO https://raw.githubusercontent.com/prosethsolutionsAI/pscyber-site-collector/main/o365.sh
sudo PSCYBER_O365_TENANT='<Directory (tenant) ID>' PSCYBER_O365_CLIENT='<Application (client) ID>' bash o365.sh
```

It asks for the app's client secret (typing hidden) and keeps it only on this box, in a
file only Wazuh can read. Before changing anything it checks Microsoft is reachable, the
secret works and the app has `ActivityFeed.Read`; if the agent will not start with the
new setting, the previous configuration is put back. Run it again to change the log
types or a renewed secret; `sudo PSCYBER_O365_REMOVE=1 bash o365.sh` stops collecting and
deletes the secret. The customer-side steps (the app to create) are in the site
onboarding guide, `microsoft365.md`.

## Remove

```bash
sudo pscyber-collector uninstall
```

Then ask Proseth to revoke the collector in the SOC platform.

## Files

| File | Purpose |
|---|---|
| `install.sh` | Installer and setup wizard |
| `heartbeat.py` | Health report to the SOC platform (runs every minute) |
| `o365.sh` | Optional: fetch the customer's Microsoft 365 audit logs (asks for the secret, tests first) |
| `VERSION` | Collector version |
