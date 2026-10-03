# PSCyber Site Collector

One Linux box at a customer site that collects the site's security logs and
sends them to the **PSCyber SOC** (Wazuh + PSCyber SOC Agentic AI):

| From the site | Sent to | Port on the collector |
|---|---|---|
| Switches, routers, firewalls, anything that speaks **syslog** | the collector | **UDP/TCP 514** |
| Devices sending **SNMP traps** | the collector | **UDP 162** |
| **Wazuh agents** on the site's Windows / Linux servers and VMs | the collector (it relays them) | **TCP 1514, 1515** |

The collector forwards everything to the SOC through **one outbound, mutual-TLS
tunnel**. Nothing inbound has to be opened on the customer's firewall.

```
 switches / firewalls ──syslog 514──┐
 devices ─────────SNMP traps 162────┤                          ┌──────────── PSCyber SOC ────────────┐
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
  to the SOC gateway** (PSCyber gives you both addresses).
- An **install command** from PSCyber (it contains a one-time token, valid 24 hours).

## Install

PSCyber creates the collector in the SOC platform (*Site collectors → New collector*)
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
   match the one PSCyber gave you (`PSCYBER_CA_FINGERPRINT`);
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
- **The box itself** (1.2.2+): the heartbeat also reports its CPU, load, memory and disk
  use - numbers only - so the SOC sees a full disk or memory shortage before it stops the
  collector.

## Reaching the site's servers (responder)

The collector also runs a **responder**: the SOC adds the site's hosts in the platform
(*SOAR → Hosts* - Linux over SSH, Windows and Active Directory domain controllers over
WinRM, network devices over SSH), and the responder checks them and runs the commands
the SOC sends, **from inside your network**. It works the same way as the heartbeat:
the collector asks the platform for work over its outbound, pinned HTTPS connection -
nothing connects in. Host logins are stored encrypted in the platform and reach the
collector only for the job that needs them; they are never written to this box.
Every command is recorded in the SOC's audit log with the analyst who ran it.

Windows hosts need WinRM enabled (`Enable-PSRemoting`) and TCP 5985 (or 5986 for HTTPS)
open from the collector.

### Ansible playbooks (version 1.2.0+)

From 1.2.0 the collector is also the site's **Ansible control node**: `update.sh` installs
`ansible-core` and `sshpass` from the distribution. A playbook runs only after a SOC
engineer drafted it and a **second** engineer approved that exact text. For the length of
one run the playbook and an inventory of the chosen hosts (with their logins) are written
to a temporary directory only root can read, then removed; the logins are masked in the
output sent back. Linux hosts are reached over SSH (become uses the same login's password),
Windows hosts over WinRM. Terraform is deliberately **not** installed here.

## Updating

```bash
sudo pscyber-collector update          # or the Update button in the SOC platform
```

The update fetches the new collector software from the SOC platform this box is enrolled
with, **pinned to the certificate saved at install**, and restarts only the heartbeat and
the responder. The enrolment, tunnel and Wazuh agent are left exactly as they are, so log
forwarding is not interrupted. A collector installed before version 1.1.1 does not have
the update command yet - run this once on it (it keeps the enrolment):

```bash
curl -sk https://<soc-platform>/collector/update.sh -o update.sh && sudo bash update.sh
```

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
them through the same tunnel. PSCyber gives you the exact command with your IDs:

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

Then ask PSCyber to revoke the collector in the SOC platform.

## Files

| File | Purpose |
|---|---|
| `install.sh` | Installer and setup wizard |
| `update.sh` | Installs / updates the collector software (heartbeat, responder, commands); used by the installer too |
| `heartbeat.py` | Health report to the SOC platform (runs every minute); starts an update when the SOC asks |
| `responder.py` | Checks the site's hosts and runs the SOC's commands and approved playbooks on them (SSH / WinRM / Ansible) |
| `o365.sh` | Optional: fetch the customer's Microsoft 365 audit logs (asks for the secret, tests first) |
| `VERSION` | Collector version |
