# service-audit.sh

[`../scripts/service-audit.sh`](../scripts/service-audit.sh) is a default-credential and weak-configuration sweep for common network services. You give it your Nmap results. It builds a host list per service and per port, then runs the right Metasploit, Nmap NSE and native checks against each list. It writes per-service evidence, lists of affected hosts, and a single `findings.csv`.

> **Authorized testing only.** The script guesses credentials online and can lock out accounts. Before you run Phase 2/3, confirm scope and the lockout policy (see [Limiting lockout risk](#limiting-lockout-risk)).

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Producing the input scans](#producing-the-input-scans)
- [How hosts are selected](#how-hosts-are-selected)
- [Run order and checks](#run-order-and-checks)
- [Options](#options)
- [Environment variables](#environment-variables)
- [Sample commands](#sample-commands)
- [Output](#output)
- [Heuristic results and verification](#heuristic-results-and-verification)
- [Troubleshooting](#troubleshooting)

## Requirements

Built for Kali Linux. [`kali-prep.sh`](../scripts/kali-prep.sh) installs anything that is missing.

| Requirement | Used for | If missing |
|---|---|---|
| `nmap` | All NSE checks | Those steps are skipped with a warning |
| `msfconsole` (Metasploit) | Login scanners, Redis, TFTP, IPMI, VNC, BlueKeep | Those steps are skipped |
| `python3` | Parsing Nmap input files | **Fatal**: the script exits |
| `showmount` (`nfs-common`) | NFS export listing | NFS showmount is skipped (the NSE scripts still run) |
| `snmpget` (`snmp`) | Confirming cleartext SNMP v1/v2c | Falls back to a heuristic version-string match |
| `oscanner` | Oracle default accounts | Oracle is skipped |
| SecLists | Default-credential wordlists in `/usr/share/seclists/Passwords/Default-Credentials` | Credential sprays for that service are skipped |
| root | `nmap -sU` (SNMP `snmp-brute`) | Warning; the UDP NSE scan fails |

Run it with `sudo`. Remember that `sudo` drops environment variables you set beforehand, so pass them **after** `sudo`:

```bash
sudo DNS_ZONES=example.local ./service-audit.sh -t tcp.xml -o audit
```

## Quick start

```bash
chmod +x service-audit.sh
```

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -o audit
```

Look at the plan first with a dry run. It builds the host lists and prints every command, but sends nothing to any target:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -o audit-dry -x
```

When it finishes, start with `audit/summary.txt` and `audit/findings.csv`.

## Producing the input scans

The script takes three kinds of Nmap output, in `.xml`, `.gnmap` or normal `.nmap` format (it detects which). Every input flag can be repeated. **XML is the most reliable format**, and scanning with `-n` keeps host lists as IPs, so the same host can be deduplicated across scans.

| Flag | Scan type | What it adds |
|---|---|---|
| `-t` | TCP **port** scan | Hosts with a service's **default port** open |
| `-T` | TCP **service** scan (`-sV`) | Hosts where Nmap **named** the service, on any port, plus default-port matches. Required for the FTP/Telnet cleartext findings and for r-services. |
| `-u` | UDP port scan | SNMP (161), TFTP (69), IPMI (623) |
| `-s` | Text file of IPs | Extra SNMP hosts (IPv4, one per line) |
| `-f` | Text file of IPs | Extra TFTP hosts (IPv4, one per line) |

Example scans that produce suitable inputs:

```bash
sudo nmap -n -Pn -p- --min-rate 2000 -iL scope.txt -oA scans/tcp-ports
```

```bash
sudo nmap -n -Pn -sV -p 21,22,23,25,53,79,111,389,445,512-514,873,1433,1521,2049,3306,3389,5432,5900-5910,6000,6379,27017 -iL scope.txt -oA scans/tcp-services
```

```bash
sudo nmap -n -Pn -sU -p 69,161,623 -iL scope.txt -oA scans/udp
```

For the service scan you can also pass every open port from the first scan, so that services on non-standard ports are found by name.

UDP rows count only when their state is `open`. `open|filtered` rows on 161/69 are dropped with a warning unless you pass `-F`.

## How hosts are selected

For each service, the script merges:

1. hosts from the **port scan** (`-t`) with the default port open,
2. hosts from the **service scan** (`-T`) whose service name matches, on **any** port,
3. hosts from the **service scan** with the default port open.

It then writes one list per port (`<svc>/<svc>-<port>.txt`) and checks each port separately. Host lists are normalized: whitespace trimmed, leading zeros removed from IPv4 octets, hostnames lowercased with any trailing dot removed, and exact duplicates dropped.

| Service | Default port | Nmap service name(s) matched | Source |
|---|---|---|---|
| ftp | 21/tcp | `ftp` | `-t` / `-T` |
| ssh | 22/tcp | `ssh` | `-t` / `-T` |
| telnet | 23/tcp | `telnet` | `-t` / `-T` |
| smtp | 25/tcp | `smtp` | `-t` / `-T` |
| dns | 53/tcp | `domain` | `-t` / `-T` (and `DNS_ZONES` must be set) |
| finger | 79/tcp | `finger` | `-t` / `-T` |
| ldap | 389/tcp | `ldap`, `ldapssl`, `ldaps` | `-t` / `-T` |
| smb | 445/tcp | `microsoft-ds`, `netbios-ssn`, `smb` | `-t` / `-T` |
| rservices | 512–514/tcp | `exec`, `login`, `shell`, `rlogin`, `rsh`, `rexec` | `-T` **only** |
| rsync | 873/tcp | `rsync` | `-t` / `-T` |
| mssql | 1433/tcp | `ms-sql-s`, `ms-sql`, `mssql` | `-t` / `-T` |
| oracle | 1521/tcp | `oracle-tns`, `oracle` | `-t` / `-T` |
| nfs | 2049/tcp | `nfs*` | `-t` / `-T` |
| mysql | 3306/tcp | `mysql`, `mariadb` | `-t` / `-T` |
| rdp | 3389/tcp | `ms-wbt-server`, `rdp` | `-t` / `-T` |
| postgres | 5432/tcp | `postgresql`, `postgres` | `-t` / `-T` |
| vnc | 5900/tcp | `vnc` | `-t` / `-T` |
| x11 | 6000/tcp | `x11` | `-t` / `-T` |
| redis | 6379/tcp | `redis` | `-t` / `-T` |
| mongodb | 27017/tcp | `mongod`, `mongodb` | `-t` / `-T` |
| tftp | 69/udp | – | `-u`, `-f` |
| snmp | 161/udp | – | `-u`, `-s` |
| ipmi | 623/udp | – | `-u` |

## Run order and checks

The checks run cheapest first. Nothing in Phase 1 guesses credentials beyond a short wordlist for Redis/SNMP/VNC. The slow Telnet and SSH sprays run last, so if you abort a long run, everything else is already on disk.

The **Suggested template** column names the [finding template](findings.md) that usually fits each result. Confirm the result manually before you report it.

### Phase 1: enumeration and unauthenticated / weak-config checks

| Service | What runs | Finding(s) written | Affected-host file(s) | Suggested template |
|---|---|---|---|---|
| nfs | `nfs-showmount,nfs-statfs` NSE, then `showmount -e` per host | export mountable by everyone; export list disclosed via showmount | `affected-public.txt`, `affected-showmount.txt` | NFS Publicly Mountable Export |
| redis | `redis-info` NSE, msf `redis_server`, then msf `redis_login` against hosts that require AUTH | unauthenticated access (no AUTH); weak/default AUTH password | `affected-unauth.txt`, `affected-defaultpass.txt` | Weak Password: Service Account (for the password case) |
| snmp | `snmp-brute` NSE (UDP), msf `snmp_login`, then `snmpget` v1/v2c with each community found | weak community string (read-only / read-write); cleartext SNMP community | `affected-readonly.txt`, `affected-readwrite.txt`, `affected-cleartext.txt`, `affected.txt` | SNMP Weak Community String - Read-Only / Read-Write; Cleartext Authentication: SNMP |
| tftp | msf `tftpbrute` | readable file via TFTP **[heuristic]** | `affected.txt` | TFTP Guessable Filename; Insecure Protocol: TFTP |
| oracle | `oscanner` (run time capped from the host count) | oscanner hit **[heuristic]** | `affected.txt` | Weak Password: Service Account |
| ssh | `ssh2-enum-algos,sshv1` NSE with `-sV` | weak SSH key exchange / host key / cipher / MAC offered; SSHv1 supported | `affected-weakalgos.txt`, `affected-sshv1.txt` | *(no dedicated template)* |
| smtp | `smtp-open-relay` NSE | open mail relay | `affected-openrelay.txt` | SMTP Open Relay |
| vnc | `vnc-info` NSE, then msf `vnc_login` (blank passwords included) | VNC no authentication; insecure VNC security type; weak/default VNC password | `affected-noauth.txt`, `affected-weaksectype.txt`, `affected-defaultpass.txt` | VNC Unauthenticated Access; Cleartext Authentication: VNC |
| smb | `smb-protocols,smb-security-mode,smb2-security-mode,smb-enum-shares` NSE. **No credential spray.** | SMBv1 enabled; SMB message signing not required; null/anonymous SMB session **[heuristic]** | `affected-smbv1.txt`, `affected-nosigning.txt`, `affected-nullsession.txt` | SMB Signing Not Enforced; SMB Null or Guest Session - Share Access / Object Enumeration |
| rdp | `rdp-enum-encryption,rdp-ntlm-info` NSE; msf BlueKeep scanner only if `RDP_BLUEKEEP=1` | RDP legacy security layer offered (NLA not enforced); BlueKeep vulnerable | `affected-weaksec.txt`, `affected-bluekeep.txt` | Outdated Software (BlueKeep) |
| ldap | `ldap-rootdse,ldap-search` NSE (`ldap.maxobjects=10`); flagged only if the anonymous search returns a `dn:` entry | LDAP anonymous search returns directory objects | `affected.txt` | LDAP Anonymous Bind |
| mongodb | `mongodb-info,mongodb-databases` NSE | MongoDB unauthenticated access **[heuristic]** | `affected.txt` | *(no dedicated template)* |
| rsync | `rsync-list-modules` NSE | rsync anonymous module listing **[heuristic]** | `affected.txt` | Unauthenticated Access: Sensitive Files (if modules are readable) |
| ipmi | msf `ipmi_cipher_zero` and `ipmi_dumphashes` (writes `ipmi-hashes.hashcat`) | IPMI cipher-zero authentication bypass; IPMI 2.0 RAKP password hash disclosure | `affected-cipher0.txt`, `affected-hashes.txt` | Insecure Protocol: IPMI Version 2.0 |
| dns | `dns-zone-transfer` NSE, once per zone in `DNS_ZONES` | DNS zone transfer (AXFR) allowed for *zone* **[heuristic]** | `affected.txt` | DNS Zone Transfer |
| finger | `finger` NSE | finger service exposes user information **[heuristic]** | `affected.txt` | Unauthenticated Username Enumeration |
| x11 | `x11-access` NSE | X11 open access (no authentication) | `affected.txt` | *(no dedicated template)* |
| rservices | Service-scan match only (presence is the finding) | insecure legacy r-service exposed | `affected.txt` | *(no dedicated template)* |

### Phases 2 and 3: credential sprays

| Phase | Services | Why this order |
|---|---|---|
| 2 (fast) | `ftp`, `mysql`, `mssql`, `postgres` | One TCP connect and one auth exchange per guess |
| 3 (slow) | `telnet`, `ssh` | Banner/prompt round-trips (Telnet) or a full KEX (SSH) per guess, 10–100× slower |

Each Phase 2/3 service runs the Metasploit `auxiliary/scanner/<svc>/<svc>_login` module with:

- the SecLists `<svc>-betterdefaultpasslist.txt` (copied into the service folder, with `user:pass` converted to `user pass`),
- `USER_AS_PASS true` and `BLANK_PASSWORDS true`,
- the inner and outer time caps described under [Environment variables](#environment-variables).

Service-specific behavior:

- **FTP and Telnet** are first flagged as *cleartext authentication protocol*, but only where the `-T` service scan identified the protocol by name. An open port alone is not enough. Suggested templates: Cleartext Authentication: FTP / Telnet.
- **FTP** runs the `ftp-anon` NSE script first. Hosts that allow anonymous login are recorded (suggested template: FTP Anonymous Access) and **left out** of the password spray.
- **SSH and Telnet** get twice the outer time cap of the other services, and use `CONNECT_TIMEOUT` for the SSH KEX / Telnet banner timeouts.

Finding written: `default/weak credentials`, with the username and password in `findings.csv`. Suggested templates: Weak Password: Local Account / Service Account, and Excessive Microsoft SQL Server Access if an MSSQL login is privileged.

## Options

```
Usage: service-audit.sh [options]
```

| Flag | Argument | Default | Meaning |
|---|---|---|---|
| `-t` | FILE | – | Nmap TCP port scan (repeatable) |
| `-T` | FILE | – | Nmap TCP service scan (repeatable) |
| `-u` | FILE | – | Nmap UDP port scan (repeatable) |
| `-s` | FILE | – | Extra SNMP host IPs, one per line (repeatable) |
| `-f` | FILE | – | Extra TFTP host IPs, one per line (repeatable) |
| `-o` | DIR | `.` | Output directory |
| `-S` | LIST | all | Comma-separated services to run (see below) |
| `-H` | SECS | `10` | Per-host / per-connection timeout |
| `-N` | SECS | `300` | Nmap `--host-timeout` |
| `-M` | SECS | `900` | Outer wall-clock cap on each `msfconsole` run (`0` = none) |
| `-m` | MINS | `10` | msf `MaxMinutesPerService` (`0` = off) |
| `-g` | N | `0` | msf `MaxGuessesPerService` (`0` = off) |
| `-B` | 0–5 | `5` | msf `BRUTEFORCE_SPEED` (0 = slowest, 5 = no delay) |
| `-1` | – | off | Stop guessing a host after its first valid credential |
| `-b` | – | off | Batch Phase 2/3 sprays into one `msfconsole` per phase |
| `-F` | – | off | UDP: also accept `open\|filtered` |
| `-x` | – | off | Dry run: build host lists and print commands, attack nothing |
| `-h` | – | – | Help (also shown when run with no arguments) |

Valid `-S` values: `ssh,ftp,telnet,mysql,mssql,postgres,oracle,redis,nfs,snmp,tftp,smtp,vnc,smb,rdp,ldap,mongodb,rsync,ipmi,dns,finger,x11,rservices`. An unknown name is a fatal error. Selecting `ssh` enables **both** the Phase 1 crypto audit and the Phase 3 password spray.

## Environment variables

Set these on the command line (after `sudo`) to override the defaults.

| Variable | Default | Meaning |
|---|---|---|
| `SECLISTS_DIR` | `/usr/share/seclists/Passwords/Default-Credentials` | Where the `*-betterdefaultpasslist.txt` files are |
| `THREADS` | `50` | msf `THREADS` |
| `CONNECT_TIMEOUT` | `10` | Same as `-H` |
| `NMAP_HOST_TIMEOUT` | `300` | Same as `-N` |
| `NMAP_EXTRA` | – | Extra arguments added to every NSE scan (e.g. `--max-retries 1`) |
| `MSF_TIMEOUT` | `900` | Same as `-M` |
| `MSF_TIMEOUT_SSH`, `MSF_TIMEOUT_TELNET` | 2 × `MSF_TIMEOUT` | Per-service outer caps. `MSF_TIMEOUT_<SVC>` works for any Phase 2/3 service. |
| `MSF_MAX_MINUTES` | `10` | Same as `-m` |
| `MSF_MAX_GUESSES` | `0` | Same as `-g` |
| `MSF_MAX_GUESSES_PER_USER` | `0` | msf `MaxGuessesPerUser` (`0` = off) |
| `BRUTEFORCE_SPEED` | `5` | Same as `-B` |
| `MSF_STOP_ON_SUCCESS` | `false` | Same as `-1` |
| `MSF_VERBOSE` | `false` | `true` logs every failed attempt to the console logs |
| `MSF_CREATE_SESSION` | `false` | `true` opens SSH/Telnet sessions on a hit |
| `MSF_BATCH` | `0` | Same as `-b` |
| `ORACLE_MAX_CAP` | `1800` | Ceiling on oscanner's derived run-time cap (seconds) |
| `REDIS_PASS_FILE` | – | Password list for `redis_login`. If unset, the script uses a SecLists `redis-betterdefaultpasslist.txt` if one exists, then SecLists' top-100 common passwords, then a 12-entry built-in list. |
| `SSH_WEAK_KEX` | `sha1\|group1-` | Regex of key-exchange algorithms to flag (`group1-` so group14/16/18 aren't matched) |
| `SSH_WEAK_HOSTKEY` | `^ssh-dss$\|^ssh-rsa$\|-cert-v00@` | Regex of host-key algorithms to flag |
| `SSH_WEAK_CIPHER` | `-cbc\|arcfour\|^3des\|blowfish\|cast128\|^none$\|^rijndael` | Regex of ciphers to flag |
| `SSH_WEAK_MAC` | `hmac-md5\|hmac-sha1\|-96\|umac-64` | Regex of MACs to flag |
| `VNC_MODERN_RE` | `Tight\|VeNCrypt\|RA2` | VNC security types that are **not** flagged |
| `RDP_BLUEKEEP` | `0` | `1` runs the BlueKeep (CVE-2019-0708) scanner. **It can crash unpatched hosts.** |
| `DNS_ZONES` | – | Comma-separated zones to try AXFR for. The DNS check is skipped unless this is set. |

Note that `ssh-rsa` and `hmac-sha1` are deliberately flagged even though they are still common. Override the regexes if you only want the clearly broken algorithms.

## Sample commands

**Full run** with all three scan types:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -o audit
```

**Dry run** to review host lists and commands before anything touches the network:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -o audit-dry -x
```

**Several scans** from different subnets or team members:

```bash
sudo ./service-audit.sh -t scans/dmz-tcp.xml -t scans/corp-tcp.xml -T scans/dmz-svc.xml -T scans/corp-svc.xml -o audit
```

**Config checks only, no credential spraying.** Leave out ftp, mysql, mssql, postgres, telnet and ssh:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -u scans/udp.xml -S nfs,redis,snmp,tftp,smtp,vnc,smb,rdp,ldap,mongodb,rsync,ipmi,dns,finger,x11,rservices -o audit-config
```

Redis, SNMP and VNC still try their short password/community lists in Phase 1. Remove them too if *any* guessing is out of scope.

**Databases only**:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -S mysql,mssql,postgres,oracle,redis,mongodb -o audit-db
```

**DNS zone transfer** against the in-scope zones:

```bash
sudo DNS_ZONES=example.local,example.com ./service-audit.sh -t scans/tcp-ports.xml -S dns -o audit-dns
```

**SNMP and TFTP from host lists** without a UDP scan:

```bash
sudo ./service-audit.sh -s snmp-hosts.txt -f tftp-hosts.txt -S snmp,tftp -o audit-udp
```

**Faster Phase 2/3** with batched msf consoles and stop-on-first-hit:

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -b -1 -o audit
```

**Tighter time budget** for a large network (5-minute msf cap, 3-minute inner budget, 5 s connect timeout):

```bash
sudo ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -M 300 -m 3 -H 5 -o audit
```

**Only flag clearly broken SSH crypto** (skip `ssh-rsa`/`hmac-sha1`):

```bash
sudo SSH_WEAK_HOSTKEY='^ssh-dss$' SSH_WEAK_MAC='hmac-md5|-96|umac-64' ./service-audit.sh -T scans/tcp-services.xml -S ssh -o audit-ssh
```

**BlueKeep check**, only when the rules of engagement allow it:

```bash
sudo RDP_BLUEKEEP=1 ./service-audit.sh -t scans/tcp-ports.xml -S rdp -o audit-rdp
```

**Custom Redis wordlist**:

```bash
sudo REDIS_PASS_FILE=/usr/share/wordlists/rockyou-top1000.txt ./service-audit.sh -t scans/tcp-ports.xml -S redis -o audit-redis
```

### Limiting lockout risk

Domain-joined services (SSH with SSSD/AD, MSSQL with Windows auth, and so on) can count failures against AD lockout. Check the domain policy first, then cap the guesses:

```bash
sudo MSF_MAX_GUESSES_PER_USER=3 ./service-audit.sh -t scans/tcp-ports.xml -T scans/tcp-services.xml -1 -B 3 -o audit
```

- `MSF_MAX_GUESSES_PER_USER` keeps each username under the lockout threshold.
- `-g N` caps the total guesses per service.
- `-1` stops guessing a host after the first valid credential.
- `-B 0`–`4` adds delays between attempts.

SMB, RDP and LDAP are never sprayed by this script.

## Output

```
audit/
├── summary.txt          # one line per check: "<label> : N host(s)"; heuristic checks are tagged [HEURISTIC]
├── findings.csv         # every finding, one row per host/port/issue
├── run.log              # timestamped log of every phase, command, warning and timeout
├── phase2-console.log   # only with -b: batched msf console output
├── phase3-console.log   # only with -b
├── .work/               # parsed scan TSVs, the generated Nmap parser, batch .rc files
└── <service>/
    ├── <svc>-<port>.txt         # host list fed to the checks for that port
    ├── affected*.txt            # deduplicated affected hosts, one IP per line
    ├── *.nmap / *.gnmap / *.xml # NSE output (-oA)
    ├── *-console.log            # msfconsole output
    ├── *-defaultpass.txt        # msf spool of the credential run
    └── ...                      # service extras: showmount-<port>.txt, ipmi-hashes.hashcat, snmp-cleartext-confirm.txt
```

When the run finishes, the script prints the summary, the number of rows in `findings.csv`, and every `affected*.txt` file with its size.

If the output directory already has a `findings.csv` or `run.log`, the script warns you and waits 3 seconds. `findings.csv`, `run.log` and `summary.txt` are **overwritten**, and the per-service folders are **merged**, not cleared. Use a new `-o` for each run if you want clean results.

### findings.csv

Columns: `ip,port,service,finding,username,password,access,evidence`. Every value is double-quoted.

A few services reuse columns for related data:

| Service | `username` | `password` | `access` |
|---|---|---|---|
| Credential sprays | login | password | – |
| ftp (anonymous) | `anonymous` | – | – |
| redis | user (6.0+ ACL) or blank | AUTH password | `read-write` |
| vnc | – | VNC password | – |
| snmp | – | community string | `read-only` / `read-write` / `confirmed` |
| nfs | – | **export path** | allowed clients |
| dns | – | **zone name** | – |

`evidence` is the path of the supporting file, relative to the output directory, or a short note such as `service scan confirmed ftp on port 21`.

## Heuristic results and verification

Some checks match loose patterns in tool output, and their results need a manual look before you report them:

- **Tagged `[HEURISTIC]` in `summary.txt`**: tftp, oracle, smb null-session, mongodb unauth, rsync anon, finger, dns zone-transfer. Their findings say "HEURISTIC - verify" or depend on output that varies between versions. For mongodb, rsync, finger and dns, the match is essentially "the NSE script returned output", so read the `.nmap` file.
- **SNMP without `snmpget`**: cleartext v1/v2c is inferred from the service-scan version string only.
- **LDAP anonymous search**: a readable rootDSE alone (the default on AD) is not flagged. A host is reported only when `ldap-search` returns directory objects without credentials. You can reproduce it for the report with:

  ```bash
  ldapsearch -x -H ldap://<dc-ip> -b "DC=example,DC=local" "(objectClass=user)" sAMAccountName
  ```

- **Credential parsing** from msf output is best-effort, because the output format changes between modules and versions. The `affected*.txt` host lists are reliable. Check the username/password columns against the `*-defaultpass.txt` spool.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Run looks hung in Phase 2/3 | msf is waiting on slow hosts. The outer cap (`-M`, default 900 s; SSH/Telnet 1800 s) kills it eventually. Lower `-m` / `-g` so msf stops cleanly *and* still writes results. |
| `killed at the Ns wall-clock cap - results are PARTIAL` | The outer cap fired before msf finished. Raise `-M` / `MSF_TIMEOUT_<SVC>`, or lower `-m` / `-g`. |
| `entry(ies) are hostnames, not IPs` | The input scan recorded hostnames. Re-scan with `-n` or use the `.xml` output so hosts dedupe correctly. |
| `UDP: dropped N open\|filtered row(s)` | Add `-F` to include them, or confirm them with a targeted scan first. |
| `snmp-brute` finds nothing | Not running as root, so `nmap -sU` failed. Use `sudo`. |
| `dns: set DNS_ZONES=... - skipping` | AXFR needs a zone name. Set `DNS_ZONES`. |
| `rservices: none found` | r-services are only taken from a `-T` service scan. |
| `<svc>: missing .../<svc>-betterdefaultpasslist.txt` | Install `seclists` or point `SECLISTS_DIR` at your copy. |
| Ctrl-C during Phase 3 | Phase 1/2 results are already on disk. With `-b`, only the modules that had finished in the batched console are kept. |
