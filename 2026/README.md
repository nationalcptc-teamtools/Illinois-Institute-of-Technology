# CPTC 2026

Tooling and reporting material for the **2026–2027 Collegiate Penetration Testing Competition (CPTC12)**. The client this season is **Butters Family Farm**.

```
2026/
├── README.md                 # this file
├── docs/
│   ├── service-audit.md      # full usage guide for service-audit.sh
│   └── findings.md           # reference for every SysReptor finding template
├── phishing/
│   ├── email.zip             # lure email template (updatebrowser.html + client logo)
│   └── dummy_site.html       # non-capturing sign-in landing page for the lure
├── scripts/
│   ├── kali-prep.sh          # one-shot Kali attack-box setup
│   ├── windows-prep.ps1      # one-shot Windows attack-box setup
│   └── service-audit.sh      # default-credential / weak-config sweep driven by Nmap output
└── templates/
    ├── design-CPTC12-2026-2027-Butters-Family-Farms.tar.gz   # SysReptor report design
    ├── template-*.tar.gz                                     # 141 SysReptor finding templates
    └── CPTC-2026-Services-SysReptor.tar.gz                   # 5 service finding templates in one archive
```

## Contents

- [Scripts](#scripts)
  - [kali-prep.sh](#kali-prepsh)
  - [windows-prep.ps1](#windows-prepps1)
  - [service-audit.sh](#service-auditsh)
- [SysReptor templates](#sysreptor-templates)
  - [Report design](#report-design)
  - [Finding templates](#finding-templates)
  - [Importing into SysReptor](#importing-into-sysreptor)
- [Phishing](#phishing)
- [Typical workflow](#typical-workflow)

---

## Scripts

### kali-prep.sh

Sets up a fresh Kali VM as the team attack box in one run. It is a **zsh** script, uses `sudo` itself, and keeps going when an individual step fails.

```bash
chmod +x kali-prep.sh
```

```bash
./kali-prep.sh
```

What it does:

| Area | Details |
|---|---|
| System | Adds a validated `/etc/sudoers.d/99-nopasswd-sudo` drop-in (passwordless sudo for the `sudo` group). Switches the APT mirror to `mirrors.ocf.berkeley.edu`. Sets `python` to Python 3. |
| APT packages | `nfs-common`, `mitm6`, `enum4linux-ng`, `bloodhound`, `neo4j`, `crackmapexec`, `smbmap`, `ldap-utils`, `ffuf`, `gobuster`, `sqlmap`, `proxychains4`, `sshuttle`, `openvpn`, `krb5-user`, `freerdp3-x11`, `testssl.sh`, `ipmitool`, `seclists`, `sublime-text`, `magic-wormhole`, and others |
| pipx | NetExec, Coercer, pre2k, sccmhunter, impacket (with the `pyOpenSSL==24.0.0` fix for `ntlmrelayx --shadowcredentials`), certipy-ad, modbus_cli, bloodhound-python, pypykatz |
| Go | Latest official Go toolchain in `/usr/local/go`, plus `gowitness` and `goexec` |
| Ruby | `evil-winrm`, `winrm`, `winrm-fs` |
| `/usr/local/bin` | `petitpotam`, `dfscoerce`, `shadowcoerce`, `printerbug`, `cheeseounce`, `kerbrute`, `rdp-sec-check.pl`, `CVE-2005-1794-check.py`, `parse-nmap`, `ligolo-proxy` (latest ligolo-ng release, resolved through the GitHub API) |
| `~/tools/ligolo` | ligolo-ng `agent` (linux amd64) and `agent.exe` (windows amd64), from the same release as the proxy, ready to copy to pivot hosts |
| `~/tools` | Clones of PKINITtools, krbrelayx, pywhisker, noPac, statistically-likely-usernames and pyautoenv. Each tool with a `requirements.txt` gets its own `.venv`, which pyautoenv activates automatically when you `cd` into it. |
| Shell | Prompt that shows the current `tun0`/`eth0` IP, aliases (`ll`, `nse`, `serve`, `myip`), `clear -x` |
| Logging | Every shell command (user and root) is logged through rsyslog `local6` to **`/var/log/commands.log`**, which is useful for the report's activity timeline |
| Other | proxychains switched to `dynamic_chain`; `bloodhound-setup` run for BloodHound CE |

When it finishes, start BloodHound with `sudo bloodhound-start` and change the default passwords: Neo4j at `http://localhost:7474` (`neo4j`/`neo4j`; update `/etc/bhapi/bhapi.json` to match) and the BloodHound UI (`admin`/`admin`).

> **Note:** Downloads in this script skip TLS certificate verification (`--no-check-certificate`, `http.sslVerify=false`, `ssl_verify_mode: 0`).

### windows-prep.ps1

Stages offensive tooling on a Windows 10/11 or Server 2016–2025 attack box. Everything is pulled at its latest version. Run it from an **elevated** PowerShell, because RSAT, DSInternals and the installers need admin rights:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; .\windows-prep.ps1
```

| Area | Details |
|---|---|
| `C:\Tools` | Rubeus, Certify, Seatbelt, SharpGPOAbuse, SharpSCCM, Whisker, SharpDPAPI, SigmaPotato, Snaffler, mimikatz, PowerUpSQL, PowerView, SharpHound.ps1, dsinternalparser.py, PingCastle |
| Windows features | RSAT AD tools and GPMC / `GroupPolicy` module (`Install-WindowsFeature` on Server, `Add-WindowsCapability` on client) |
| PowerShell | DSInternals module (from the PowerShell Gallery) |
| Applications | Notepad++, Python 3 (latest, on PATH), MobaXterm Home |

Each step reports `[+]` or `[-]`, and the script ends with a list of the steps that failed so you can re-run them. Expect Microsoft Defender to quarantine several of the downloaded binaries unless `C:\Tools` is excluded.

### service-audit.sh

A default-credential and weak-configuration sweep for 23 network services, driven by your Nmap output. Give it TCP port, TCP service and UDP scans (XML, gnmap or normal format). It builds per-service host lists and runs Metasploit login scanners, Nmap NSE scripts and native probes in three phases, cheapest first:

1. **Phase 1** (enumeration and unauthenticated / weak-config checks): NFS, Redis, SNMP, TFTP, Oracle, SSH crypto, SMTP open relay, VNC, SMB, RDP, LDAP, MongoDB, rsync, IPMI, DNS AXFR, finger, X11, r-services
2. **Phase 2** (fast credential sprays): FTP, MySQL, MSSQL, PostgreSQL
3. **Phase 3** (slow credential sprays): Telnet, SSH

Output is `summary.txt`, `findings.csv` (one row per host/port/issue), `run.log`, and a folder per service with evidence and `affected*.txt` host lists.

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -o audit
```

**→ Full guide with options, environment variables, sample commands, output format and verification notes: [docs/service-audit.md](docs/service-audit.md)**

> **Authorized testing only.** It guesses credentials online and can lock out accounts. Run with `-x` (dry run) first, and check the lockout policy before Phase 2/3.

---

## SysReptor templates

The [`templates/`](templates/) folder holds exports from the team's SysReptor instance (version 2026.68) in SysReptor's native archive format.

### Report design

**`design-CPTC12-2026-2027-Butters-Family-Farms.tar.gz`** is the report design (SysReptor "project type"). It contains the PDF layout, styles, cover logo and the report and finding fields. Its defaults are pre-filled for this engagement: customer *Butters Family Farm*, team *CyberHawks*, *Great Lakes Regional*, 2 days on 2026-10-24 and 2026-10-25.

PDF structure:

1. **Cover**: report title, customer, date, team and region
2. **Engagement Notice**: confidentiality notice, disclaimer, rules of engagement and safety notice, document history
3. **Table of Contents**
4. **Executive Summary**: overview, key strengths, summary of findings (counts are generated), overall risk, opportunities for improvement
5. **Technical Summary**: scope, network topology, testing methodology, attack path analysis, strategic recommendations
6. **Security Vulnerabilities Overview**: table of all findings with their risk level and CVSS score
7. **Technical Findings**: grouped Critical → High → Medium → Low → Informational, each with its risk level, CVSS score and vector, affected systems and quick fix, followed by the security overview, technical analysis, business impact, proof of exploitation, remediation and references
8. **Appendix**: severity scale, tools and technologies, assessment artifacts / cleanup log

Many report sections ship with **`TODO`** placeholder text (executive summary, scope, strengths, overall risk, improvement, topology, attack path). Search the rendered PDF for "TODO" before you submit.

> **The risk level in the PDF comes from each finding's `severity` field** (`info` to `critical`). The PDF uses the CVSS level only when `severity` is empty, and prints the CVSS score and vector as a supporting reference. Findings are ordered by severity, then CVSS score, then title. See [docs/findings.md](docs/findings.md#how-severity-is-shown-in-the-report).

### Finding templates

The 141 **`template-<Title>.tar.gz`** files are pre-written findings. They have the summary, technical description, vulnerability details, impact, recommendation (remediation plus compensating controls), short recommendation, references and a default CVSS 4.0 vector. **Affected components** and **Proof of Exploitation** are left empty for you to fill in during the engagement.

| Environment | Critical | High | Medium | Low | Total | Examples |
|---|---:|---:|---:|---:|---:|---|
| Active Directory | 1 | 40 | 29 | 2 | 72 | ADCS ESC1–ESC17, delegation, coercion, Kerberos, NTLM relay, shared/weak passwords, Zerologon, noPac |
| Web Application | 11 | 16 | 13 | 3 | 43 | Injection (SQL, NoSQL, LDAP, command, SSTI), XSS, CSRF, SSRF, IDOR, JWT, file upload/inclusion |
| Network Service | 7 | 9 | 7 | 2 | 25 | FTP/TFTP/NFS/iSCSI exposure, SNMP communities, cleartext protocols, IPMI, SMTP relay, VNC |
| Unclassified | – | – | – | – | 1 | *SSH: guessable user and password* (unfinished) |

**→ Field definitions and the full list of findings with severity, CVSS score and tags: [docs/findings.md](docs/findings.md)**

**`CPTC-2026-Services-SysReptor.tar.gz`** is a separate archive with five more service findings: *VNC Access without Authentication*, *Anonymous FTP Access to Restricted Files*, *SMB Share Access without Authentication*, *Weak SSH Credentials* and *Weak Telnet Credentials*. It imports the same way as the other templates.

### Importing into SysReptor

**Web UI**

1. **Designs → Import** and upload `design-CPTC12-2026-2027-Butters-Family-Farms.tar.gz`.
2. **Templates → Import** and upload each `template-*.tar.gz` you need.
3. Create the project from the imported design. In the project, use **Add finding → From template**.

**Command line** (on the SysReptor host, from the directory with its `docker-compose.yml`):

```bash
docker compose exec -T app python3 manage.py importdemodata --type=design < design-CPTC12-2026-2027-Butters-Family-Farms.tar.gz
```

```bash
for f in template-*.tar.gz; do docker compose exec -T app python3 manage.py importdemodata --type=template < "$f"; done
```

The templates fit any design whose finding field IDs and types match (`title`, `severity`, `cvss`, `affected_components`, `summary`, `short_recommendation`, `description`, `impact`, `recommendation`, `references`, `vulnerability`, `exploit`, `environment`). Labels, help text and defaults don't need to match. Check what is already on the instance before importing, so you don't end up with duplicate templates.

---

## Phishing

The [`phishing/`](phishing/) folder holds a ready-made browser-compliance pretext for the Butters Family Farm social-engineering portion. Use it only if phishing is in scope under the rules of engagement.

The pretext runs in two steps. The **email** tells staff they must verify their workstation browser settings "ASAP" or be referred to their manager. Its button leads to the **landing page**, which asks for their work email and password.

| File | What it is |
|---|---|
| `email.zip` | The phishing **email** template. Unzips to a `Phishing Template/` folder (details below). |
| `dummy_site.html` | The **landing page**: a self-contained "Browser Compliance Verification" sign-in page (the logo is embedded as base64). On submit it clears the fields and shows a *training simulation complete* message. It never sends or stores the credentials. |

### email.zip

| File in `Phishing Template/` | Contents |
|---|---|
| `updatebrowser.html` | HTML email body. It has a dark theme, the logo at the top, a "Butter Family Farms IT Operations" header and a compliance notice signed by the *IT Security Team*. A **Verify Browser Compliance** button links to `https://YOUR-APPROVED-IT-PORTAL.example`. The page `<title>`, *IT Security Compliance Notification*, works as the subject line. |
| `butters-family-farm.png` | Client logo (671×398, longhorn "B" on a white background). The email loads it by relative path (`src="butters-family-farm.png"`). |

To use it, unzip it and load `updatebrowser.html` into your sending tool (for example a GoPhish *Email Template* → *Import Email* / HTML tab). Then:

- **Set the link.** Replace `https://YOUR-APPROVED-IT-PORTAL.example` with the URL where you host `dummy_site.html`. In GoPhish, use `{{.URL}}` so each click is tracked per recipient.
- **Fix the logo reference.** A relative image path won't resolve in a recipient's mail client. Attach the PNG inline (CID) or host it and use an absolute URL.
- **Fix the client name.** The email text says *Butter Family Farms*, while the logo and the rest of the engagement material say *Butters*.
- **Check rendering.** The styles live in a `<head>` `<style>` block, and some clients (notably Outlook desktop) ignore parts of it. Send a test to yourself first.

### Results

Neither file records anything itself. Opens and clicks come from your sending tool or from the web server log entries for `dummy_site.html`. Submitting the form sends **no request at all**, because the page cancels the submit in JavaScript. To count submissions, add a request to the submit handler that carries no field values (for example, `fetch('/submitted')`). Report the results as counts, not captured credentials.

---

## Typical workflow

1. Build the attack boxes with `kali-prep.sh` / `windows-prep.ps1`.
2. Run the Nmap port, service and UDP scans of the scope (see [Producing the input scans](docs/service-audit.md#producing-the-input-scans)).
3. Run `service-audit.sh` against them (`-x` first) and work through `summary.txt` / `findings.csv`.
4. Verify each hit manually. Heuristic checks are flagged in `summary.txt`.
5. In SysReptor, add each confirmed issue from its template (the [suggested template](docs/service-audit.md#run-order-and-checks) column maps audit results to templates), then fill in **Affected Components** and **Proof of Exploitation**, and confirm the **Severity** (it drives the report) and the CVSS vector.
6. Replace the `TODO` text in the report sections and use `/var/log/commands.log` for the artifacts and cleanup log.
