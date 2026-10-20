#!/usr/bin/env bash
#
# service-audit.sh - Default-credential / weak-auth sweep for common services
#
# Parses Nmap TCP port scans, TCP service scans and UDP port scans, builds
# per-service / per-port host lists, then runs Metasploit login scanners,
# oscanner, nmap ftp-anon, snmp-brute + msf snmp_login, msf tftpbrute,
# msf redis_server + nmap redis-info, nmap ssh2-enum-algos/sshv1,
# nmap smtp-open-relay, nmap vnc-info + msf vnc_login, showmount -e for NFS,
# nmap smb-*/rdp-*/ldap-rootdse/mongodb-*/rsync-list-modules/x11-access/finger/
# dns-zone-transfer, and msf ipmi_cipher_zero + ipmi_dumphashes.
#
# FTP and Telnet are additionally flagged as cleartext-auth protocols, but only
# where the TCP service scan (-T) confirms the protocol by name - never on a
# bare open-port match. SNMP v1/v2c (cleartext community, no v3 auth/privacy)
# is flagged by a direct snmpget probe with a discovered community.
#
# Run order is cheapest-first: nmap NSE scans and single-connect probes run
# before any credential guessing, and telnet/ssh sprays run dead last, so a
# run you have to abort still leaves you with everything else on disk.
#
# Kali Linux. Requires: nmap, msfconsole, oscanner, showmount (nfs-common),
#                       seclists, python3.
#
# AUTHORISED TESTING ONLY. This performs online credential guessing and can
# lock out accounts. Confirm scope and lockout policy before running.
#

set -uo pipefail

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
SECLISTS_DIR="${SECLISTS_DIR:-/usr/share/seclists/Passwords/Default-Credentials}"
THREADS="${THREADS:-50}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"      # per-host / per-connection, seconds
NMAP_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT:-300}" # nmap --host-timeout, seconds

# --- msfconsole run caps -------------------------------------------------- #
# MSF_TIMEOUT is the OUTER wall-clock cap (GNU timeout) on each msfconsole
# invocation. It is the only thing that can stop a wedged msf process.
# 0 = no cap (the old default - this is what makes the script look hung).
MSF_TIMEOUT="${MSF_TIMEOUT:-900}"             # seconds per msf run, 0 = unlimited
# Per-service override: MSF_TIMEOUT_SSH, MSF_TIMEOUT_TELNET, MSF_TIMEOUT_MYSQL...
# Left empty here; resolved after arg parsing to 2x MSF_TIMEOUT so that
# "-M 0" (no cap) really means no cap everywhere.
MSF_TIMEOUT_SSH="${MSF_TIMEOUT_SSH:-}"
MSF_TIMEOUT_TELNET="${MSF_TIMEOUT_TELNET:-}"

# --- msf INNER (module-level) budget -------------------------------------- #
# These make msf stop cleanly and still write findings, unlike the outer cap.
MSF_MAX_MINUTES="${MSF_MAX_MINUTES:-10}"      # MaxMinutesPerService, 0 = off
MSF_MAX_GUESSES="${MSF_MAX_GUESSES:-0}"       # MaxGuessesPerService, 0 = off
MSF_MAX_GUESSES_PER_USER="${MSF_MAX_GUESSES_PER_USER:-0}"  # MaxGuessesPerUser, 0 = off
BRUTEFORCE_SPEED="${BRUTEFORCE_SPEED:-5}"     # 0=slowest (delays), 5=no delay
MSF_STOP_ON_SUCCESS="${MSF_STOP_ON_SUCCESS:-false}"  # true = stop host at 1st hit
MSF_VERBOSE="${MSF_VERBOSE:-false}"           # true = log every failed attempt
MSF_CREATE_SESSION="${MSF_CREATE_SESSION:-false}"    # ssh/telnet: open shells on hit
# 1 = run all Phase 2/3 credential sprays in ONE msfconsole per phase instead of
# one per service (fewer ~15s cold starts). Trade-off: a single outer wall-clock
# cap per phase replaces the per-service caps (msf's inner MaxMinutesPerService
# still bounds each module); Ctrl-C keeps only already-finished modules.
MSF_BATCH="${MSF_BATCH:-0}"

ORACLE_MAX_CAP="${ORACLE_MAX_CAP:-1800}"      # ceiling on the derived oscanner cap
NMAP_EXTRA="${NMAP_EXTRA:-}"

# SSH weak-algorithm denylists - extended regex per category, matched against
# each algorithm ssh2-enum-algos reports. ssh-rsa (SHA-1 sig) and hmac-sha1 are
# deprecated-but-common and deliberately flagged; override to taste.
SSH_WEAK_KEX="${SSH_WEAK_KEX:-sha1|group1-}"   # group1- only; not group14/16/18
SSH_WEAK_HOSTKEY="${SSH_WEAK_HOSTKEY:-^ssh-dss$|^ssh-rsa$|-cert-v00@}"
SSH_WEAK_CIPHER="${SSH_WEAK_CIPHER:--cbc|arcfour|^3des|blowfish|cast128|^none$|^rijndael}"
SSH_WEAK_MAC="${SSH_WEAK_MAC:-hmac-md5|hmac-sha1|-96|umac-64}"

OUTDIR="."
DRYRUN=0
UDP_INCLUDE_FILTERED=0
ALL_SERVICES="ssh,ftp,telnet,mysql,mssql,postgres,oracle,redis,nfs,snmp,tftp,smtp,vnc,smb,rdp,ldap,mongodb,rsync,ipmi,dns,finger,x11,rservices"
SELECTED="$ALL_SERVICES"

declare -a TCP_PORTSCANS=() TCP_SVCSCANS=() UDP_SCANS=() SNMP_LISTS=() TFTP_LISTS=()
BATCH_RC=""; declare -a BATCH_ITEMS=()   # batched-msf resource file + deferred parses

# service | msf module path | default tcp port | nmap service-name regex
# Ordered fastest -> slowest. telnet and ssh are deliberately last: their
# per-attempt cost (banner negotiation / KEX) is 10-100x a DB login.
SERVICES=(
  "ftp|ftp/ftp_login|21|^ftp$"
  "mysql|mysql/mysql_login|3306|^(mysql|mariadb)$"
  "mssql|mssql/mssql_login|1433|^(ms-sql-s|ms-sql|mssql)$"
  "postgres|postgres/postgres_login|5432|^(postgresql|postgres)$"
  "telnet|telnet/telnet_login|23|^telnet$"
  "ssh|ssh/ssh_login|22|^ssh$"
)
# Execution phases (see dispatcher at the bottom of this script).
PHASE_FAST_TCP=(ftp mysql mssql postgres)
PHASE_SLOW_TCP=(telnet ssh)
ORACLE_PORT=1521 ; ORACLE_RE='^(oracle-tns|oracle)$'
REDIS_PORT=6379  ; REDIS_RE='^redis$'
NFS_PORT=2049    ; NFS_RE='^nfs'
SMTP_PORT=25     ; SMTP_RE='^smtp$'
VNC_PORT=5900    ; VNC_RE='^vnc$'
# VNC security types considered modern/strong - everything else is flagged.
VNC_MODERN_RE="${VNC_MODERN_RE:-Tight|VeNCrypt|RA2}"
SMB_PORT=445     ; SMB_RE='^(microsoft-ds|netbios-ssn|smb)$'
RDP_PORT=3389    ; RDP_RE='^(ms-wbt-server|rdp)$'
LDAP_PORT=389    ; LDAP_RE='^(ldap|ldapssl|ldaps)$'
MONGODB_PORT=27017 ; MONGODB_RE='^mongod(b)?$'
RSYNC_PORT=873   ; RSYNC_RE='^rsync$'
IPMI_PORT=623    ; IPMI_RE='^(asf-rmcp|ipmi)$'
DNS_PORT=53      ; DNS_RE='^domain$'
FINGER_PORT=79   ; FINGER_RE='^finger$'
X11_PORT=6000    ; X11_RE='^x11$'
RSERVICES_RE='^(exec|login|shell|rlogin|rsh|rexec)$'   # r-services (512/513/514)
# BlueKeep (CVE-2019-0708) scanning can crash unpatched hosts, so it is OFF by
# default; set RDP_BLUEKEEP=1 only when the scope allows it.
RDP_BLUEKEEP="${RDP_BLUEKEEP:-0}"
# DNS AXFR needs a zone name, not just an IP; set DNS_ZONES=a.com,b.com to test.
DNS_ZONES="${DNS_ZONES:-}"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_blu=$'\e[36m'; c_rst=$'\e[0m'
ts() { date '+%Y-%m-%d %H:%M:%S'; }

_rlog() { [[ -n "${RUNLOG:-}" ]] && printf '[%s] %s\n' "$(ts)" "$*" >> "$RUNLOG"; return 0; }
log()  { printf '%s[*]%s %s\n' "$c_blu" "$c_rst" "$*"; _rlog "INFO  $*"; }
ok()   { printf '%s[+]%s %s\n' "$c_grn" "$c_rst" "$*"; _rlog "OK    $*"; }
warn() { printf '%s[!]%s %s\n' "$c_yel" "$c_rst" "$*" >&2; _rlog "WARN  $*"; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_rst" "$*" >&2; _rlog "FATAL $*"; exit 1; }
logcmd() { _rlog "CMD   (cwd=$1) $2"; }

strip_ansi() { sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g'; }

# Canonicalise + dedupe a host list on stdin.
#  - trims whitespace, drops blank lines
#  - strips leading zeros from IPv4 octets (010.0.0.1 -> 10.0.0.1)
#  - lowercases hostnames, strips a trailing dot (WEB.LAN. -> web.lan)
#  - exact-match dedupe in awk, THEN sort -V (never `sort -uV`, whose version
#    comparison can collapse two distinct strings into one)
dedupe_hosts() {
  awk '
    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0) }
    $0 == "" { next }
    {
      if ($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        split($0, o, "."); s = ""
        for (i = 1; i <= 4; i++) s = s (i > 1 ? "." : "") (o[i] + 0)
        $0 = s
      } else {
        $0 = tolower($0); sub(/\.$/, "", $0)
      }
      if (!seen[$0]++) print
    }' | sort -V
}

dedupe_file() { # <path> - rewrite in place, deduped
  local f="$1"
  [[ -r "$f" ]] || return 0
  dedupe_hosts < "$f" > "$f.dedup" && mv "$f.dedup" "$f"
}

# Warn once if a host list contains non-IP entries, which cannot be deduped
# against the same host's IP form appearing in another scan.
check_hostnames() { # <path> <label>
  local f="$1" label="$2" n
  [[ -r "$f" ]] || return 0
  n="$(grep -cvE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$' "$f" 2>/dev/null)" || n=0
  [[ "$n" -gt 0 ]] && warn "$label: $n entry(ies) are hostnames, not IPs - cannot dedupe against their IP form (scan with -n, or feed .xml)"
  return 0
}

csv_esc() { printf '"%s"' "$(printf '%s' "${1:-}" | sed 's/"/""/g')"; }
add_finding() { # ip port service finding username password access evidence
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_esc "${1:-}")" "$(csv_esc "${2:-}")" "$(csv_esc "${3:-}")" "$(csv_esc "${4:-}")" \
    "$(csv_esc "${5:-}")" "$(csv_esc "${6:-}")" "$(csv_esc "${7:-}")" "$(csv_esc "${8:-}")" \
    >> "$FINDINGS"
}

usage() {
cat <<EOF
Usage: $0 [options]

Input (all repeatable):
  -t FILE   Nmap TCP *port* scan     (.xml / .gnmap / .nmap)
  -T FILE   Nmap TCP *service* scan  (.xml / .gnmap / .nmap)
  -u FILE   Nmap UDP port scan       (.xml / .gnmap / .nmap)
  -s FILE   Text file of SNMP host IPs, one per line
  -f FILE   Text file of TFTP host IPs, one per line

Options:
  -o DIR    Output directory (default: current directory)
  -S LIST   Comma-separated services (default: all)
            ${ALL_SERVICES}
  -H SECS   Per-host / per-connection timeout      (default: ${CONNECT_TIMEOUT})
  -N SECS   Nmap --host-timeout                    (default: ${NMAP_HOST_TIMEOUT})
  -M SECS   Wall-clock cap on each msfconsole run  (default: ${MSF_TIMEOUT}, 0 = none)
  -m MINS   msf MaxMinutesPerService               (default: ${MSF_MAX_MINUTES}, 0 = off)
  -g N      msf MaxGuessesPerService               (default: ${MSF_MAX_GUESSES}, 0 = off)
  -B 0-5    msf BRUTEFORCE_SPEED                   (default: ${BRUTEFORCE_SPEED})
  -1        Stop guessing a host after the first valid credential
  -b        Batch Phase 2/3 sprays into one msfconsole per phase (fewer cold
            starts; one outer cap per phase instead of per-service)
  -F        UDP: also accept state 'open|filtered' (default: 'open' only)
  -x        Dry run: build host lists + print commands, attack nothing
  -h        Help

Run order (fastest / most bounded first):
  PHASE 1 (no credential guessing): nfs redis snmp tftp oracle ssh-crypto smtp
          vnc smb rdp ldap mongodb rsync ipmi dns finger x11 rservices
  PHASE 2 (fast cred sprays):  ftp mysql mssql postgres
  PHASE 3 (slow cred sprays):  telnet ssh

Env overrides: SECLISTS_DIR THREADS CONNECT_TIMEOUT NMAP_HOST_TIMEOUT
               MSF_TIMEOUT MSF_TIMEOUT_SSH MSF_TIMEOUT_TELNET (per-service caps)
               MSF_MAX_MINUTES MSF_MAX_GUESSES MSF_MAX_GUESSES_PER_USER
               BRUTEFORCE_SPEED MSF_STOP_ON_SUCCESS MSF_VERBOSE MSF_BATCH
               MSF_CREATE_SESSION ORACLE_MAX_CAP NMAP_EXTRA REDIS_PASS_FILE
               SSH_WEAK_KEX SSH_WEAK_HOSTKEY SSH_WEAK_CIPHER SSH_WEAK_MAC
               VNC_MODERN_RE RDP_BLUEKEEP DNS_ZONES

Outputs: <service>/<service>-<port>.txt, <service>/affected*.txt,
         run.log, findings.csv, summary.txt
EOF
exit 0
}

want() { [[ ",$SELECTED," == *",$1,"* ]]; }

# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #
[[ $# -eq 0 ]] && usage
while getopts ":t:T:u:s:f:o:S:H:N:M:m:g:B:b1Fxh" opt; do
  case "$opt" in
    t) TCP_PORTSCANS+=("$OPTARG") ;;
    T) TCP_SVCSCANS+=("$OPTARG")  ;;
    u) UDP_SCANS+=("$OPTARG")     ;;
    s) SNMP_LISTS+=("$OPTARG")    ;;
    f) TFTP_LISTS+=("$OPTARG")    ;;
    o) OUTDIR="$OPTARG"           ;;
    S) SELECTED="$OPTARG"         ;;
    H) CONNECT_TIMEOUT="$OPTARG"  ;;
    N) NMAP_HOST_TIMEOUT="$OPTARG";;
    M) MSF_TIMEOUT="$OPTARG"      ;;
    m) MSF_MAX_MINUTES="$OPTARG"  ;;
    g) MSF_MAX_GUESSES="$OPTARG"  ;;
    B) BRUTEFORCE_SPEED="$OPTARG" ;;
    1) MSF_STOP_ON_SUCCESS=true   ;;
    b) MSF_BATCH=1                ;;
    F) UDP_INCLUDE_FILTERED=1     ;;
    x) DRYRUN=1                   ;;
    h) usage                      ;;
    \?) die "Unknown option -$OPTARG" ;;
    :)  die "Option -$OPTARG requires an argument" ;;
  esac
done

# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
for f in "${TCP_PORTSCANS[@]}" "${TCP_SVCSCANS[@]}" "${UDP_SCANS[@]}" \
         "${SNMP_LISTS[@]}" "${TFTP_LISTS[@]}"; do
  [[ -r "$f" ]] || die "Cannot read input file: $f"
done

command -v python3 >/dev/null || die "python3 not found"

# validate -S
SELECTED="$(tr -d '[:space:]' <<<"$SELECTED" | tr '[:upper:]' '[:lower:]')"
IFS=',' read -r -a _sel <<<"$SELECTED"
for s in "${_sel[@]}"; do
  [[ -z "$s" ]] && continue
  [[ ",$ALL_SERVICES," == *",$s,"* ]] || die "Unknown service '$s' in -S. Valid: $ALL_SERVICES"
done

for bin in nmap msfconsole oscanner showmount snmpget; do
  command -v "$bin" >/dev/null || warn "$bin not in PATH - related steps will be skipped"
done
[[ -d "$SECLISTS_DIR" ]] || warn "SecLists dir missing: $SECLISTS_DIR  (apt install seclists)"
[[ "$(id -u)" -eq 0 ]] || warn "Not root: 'nmap -sU' (snmp-brute) will fail. Re-run with sudo."

mkdir -p "$OUTDIR" || die "Cannot create $OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
if [[ -e "$OUTDIR/findings.csv" || -e "$OUTDIR/run.log" ]]; then
  warn "Output dir already contains results from a previous run:"
  warn "  $OUTDIR  -  findings.csv / run.log / summary.txt will be OVERWRITTEN"
  warn "  (per-service folders are merged, not cleared. Ctrl-C now, or use -o)"
  sleep 3
fi
WORK="$OUTDIR/.work"; mkdir -p "$WORK"
SUMMARY="$OUTDIR/summary.txt"; : > "$SUMMARY"
RUNLOG="$OUTDIR/run.log";      : > "$RUNLOG"
FINDINGS="$OUTDIR/findings.csv"
echo 'ip,port,service,finding,username,password,access,evidence' > "$FINDINGS"

_rlog "START $0 $*"
_rlog "CONF  threads=$THREADS connect_timeout=$CONNECT_TIMEOUT nmap_host_timeout=$NMAP_HOST_TIMEOUT dryrun=$DRYRUN"
_rlog "CONF  msf_timeout=${MSF_TIMEOUT} ssh=${MSF_TIMEOUT_SSH} telnet=${MSF_TIMEOUT_TELNET} max_minutes=${MSF_MAX_MINUTES} max_guesses=${MSF_MAX_GUESSES} speed=${BRUTEFORCE_SPEED} stop_on_success=${MSF_STOP_ON_SUCCESS}"

[[ "$MSF_TIMEOUT" =~ ^[0-9]+$ ]] || MSF_TIMEOUT=0   # empty/garbage -> no cap
# telnet/ssh get double the budget by default - they are the slow ones.
[[ -n "$MSF_TIMEOUT_SSH"    ]] || MSF_TIMEOUT_SSH=$(( MSF_TIMEOUT * 2 ))
[[ -n "$MSF_TIMEOUT_TELNET" ]] || MSF_TIMEOUT_TELNET=$(( MSF_TIMEOUT * 2 ))
NMAP_TO=(--host-timeout "${NMAP_HOST_TIMEOUT}s")

# Wall-clock cap for a given service, falling back to the global one.
msf_cap_for() { # <svc>
  local v="MSF_TIMEOUT_${1^^}"
  local c="${!v:-$MSF_TIMEOUT}"
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  printf '%s' "$c"
}

# Datastore options shared by every AuthBrute-based login module.
msf_brute_opts() {
  local o=""
  o+="set BRUTEFORCE_SPEED ${BRUTEFORCE_SPEED} ; "
  o+="set VERBOSE ${MSF_VERBOSE} ; "
  o+="set STOP_ON_SUCCESS ${MSF_STOP_ON_SUCCESS} ; "
  [[ "$MSF_MAX_MINUTES"          =~ ^[1-9][0-9]*$ ]] && o+="set MaxMinutesPerService ${MSF_MAX_MINUTES} ; "
  [[ "$MSF_MAX_GUESSES"          =~ ^[1-9][0-9]*$ ]] && o+="set MaxGuessesPerService ${MSF_MAX_GUESSES} ; "
  [[ "$MSF_MAX_GUESSES_PER_USER" =~ ^[1-9][0-9]*$ ]] && o+="set MaxGuessesPerUser ${MSF_MAX_GUESSES_PER_USER} ; "
  printf '%s' "$o"
}

phase() { printf '\n%s===== %s =====%s\n' "$c_blu" "$*" "$c_rst"; _rlog "PHASE $*"; }

# --------------------------------------------------------------------------- #
# Nmap parser (xml / gnmap / nmap normal) -> TSV: ip port proto state svc ver
# --------------------------------------------------------------------------- #
PARSER="$WORK/parse_nmap.py"
cat > "$PARSER" <<'PYEOF'
#!/usr/bin/env python3
import sys, re
import xml.etree.ElementTree as ET

def emit(rows):
    for r in rows:
        print("\t".join(str(x) if x is not None else "" for x in r))

def parse_xml(path):
    rows = []
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        print("[!] XML parse failed %s: %s" % (path, e), file=sys.stderr)
        return rows
    for host in root.findall('host'):
        addr = None
        for a in host.findall('address'):
            if a.get('addrtype') in ('ipv4', 'ipv6'):
                addr = a.get('addr'); break
        if not addr:
            continue
        ports = host.find('ports')
        if ports is None:
            continue
        for p in ports.findall('port'):
            st = p.find('state')
            if st is None:
                continue
            svc = p.find('service')
            name = svc.get('name', '') if svc is not None else ''
            ver = ''
            if svc is not None:
                ver = ' '.join(x for x in (svc.get('product',''), svc.get('version','')) if x)
            rows.append((addr, p.get('portid'), p.get('protocol'),
                         st.get('state',''), name, ver))
    return rows

def parse_gnmap(path):
    rows = []
    rx = re.compile(r'^Host:\s+(\S+)\s+\([^)]*\)\s+Ports:\s+(.*)$')
    with open(path, errors='replace') as fh:
        for line in fh:
            m = rx.match(line.strip())
            if not m:
                continue
            ip = m.group(1)
            for ent in m.group(2).split(','):
                f = ent.strip().split('/')
                if len(f) < 5 or not f[0].isdigit():
                    continue
                ver = f[6] if len(f) > 6 else ''
                rows.append((ip, f[0], f[2], f[1], f[4], ver))
    return rows

def parse_normal(path):
    rows = []
    ip = None
    # "Nmap scan report for <name> (<ip>)" or "... for <ip>" or "... for <name>"
    rx_host = re.compile(r'^Nmap scan report for (\S+)(?:\s+\(([0-9a-fA-F.:]+)\))?\s*$')
    rx_port = re.compile(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$')
    with open(path, errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n')
            m = rx_host.match(line)
            if m:
                # prefer the parenthesised IP; fall back to the bare token
                ip = m.group(2) or m.group(1)
                continue
            m = rx_port.match(line)
            if m and ip:
                port, proto, state, name, ver = m.groups()
                rows.append((ip, port, proto, state, name, ver.strip()))
    return rows

def detect(path):
    with open(path, errors='replace') as fh:
        head = fh.read(4096)
    if head.lstrip().startswith('<?xml') or '<nmaprun' in head:
        return parse_xml
    if re.search(r'^Host:\s.*Ports:', head, re.M):
        return parse_gnmap
    return parse_normal

for path in sys.argv[1:]:
    try:
        emit(detect(path)(path))
    except Exception as e:
        print("[!] Failed to parse %s: %s" % (path, e), file=sys.stderr)
PYEOF

TCP_PORT_TSV="$WORK/tcp-portscan.tsv"
TCP_SVC_TSV="$WORK/tcp-svcscan.tsv"
UDP_TSV="$WORK/udp.tsv"
: > "$TCP_PORT_TSV"; : > "$TCP_SVC_TSV"; : > "$UDP_TSV"

[[ ${#TCP_PORTSCANS[@]} -gt 0 ]] && python3 "$PARSER" "${TCP_PORTSCANS[@]}" | awk -F'\t' '$3=="tcp"' > "$TCP_PORT_TSV"
[[ ${#TCP_SVCSCANS[@]}  -gt 0 ]] && python3 "$PARSER" "${TCP_SVCSCANS[@]}"  | awk -F'\t' '$3=="tcp"' > "$TCP_SVC_TSV"
if [[ ${#UDP_SCANS[@]} -gt 0 ]]; then
  if [[ $UDP_INCLUDE_FILTERED -eq 1 ]]; then
    python3 "$PARSER" "${UDP_SCANS[@]}" | awk -F'\t' '$3=="udp" && $4 ~ /^open/' > "$UDP_TSV"
  else
    python3 "$PARSER" "${UDP_SCANS[@]}" | awk -F'\t' '$3=="udp"' > "$WORK/udp-all.tsv"
    awk -F'\t' '$4=="open"' "$WORK/udp-all.tsv" > "$UDP_TSV"
    filt=$(awk -F'\t' '$4 ~ /^open\|/ && ($2=="161" || $2=="69")' "$WORK/udp-all.tsv" | wc -l)
    [[ $filt -gt 0 ]] && warn "UDP: dropped $filt open|filtered row(s) on 161/69 - use -F to include them"
  fi
fi

log "Parsed: $(wc -l < "$TCP_PORT_TSV") TCP portscan rows, $(wc -l < "$TCP_SVC_TSV") TCP service rows, $(wc -l < "$UDP_TSV") UDP rows"

# --------------------------------------------------------------------------- #
# Host-list builders
# --------------------------------------------------------------------------- #
build_hostlists() { # <svc> <default_port> <svc_name_regex> <outdir>
  local svc="$1" defport="$2" re="$3" dir="$4"
  local pairs="$WORK/$svc.pairs"; : > "$pairs"

  awk -F'\t' -v p="$defport" '$4 ~ /^open/ && $2==p {print $1"\t"$2}' "$TCP_PORT_TSV" >> "$pairs"
  awk -F'\t' -v re="$re"     '$4 ~ /^open/ && $5 ~ re {print $1"\t"$2}' "$TCP_SVC_TSV"  >> "$pairs"
  awk -F'\t' -v p="$defport" '$4 ~ /^open/ && $2==p {print $1"\t"$2}' "$TCP_SVC_TSV"  >> "$pairs"

  sort -u "$pairs" -o "$pairs"
  [[ -s "$pairs" ]] || return 1

  local port
  while read -r port; do
    awk -F'\t' -v p="$port" '$2==p {print $1}' "$pairs" | dedupe_hosts > "$dir/$svc-$port.txt"
    check_hostnames "$dir/$svc-$port.txt" "$svc/$svc-$port.txt"
    ok "$svc: $(wc -l < "$dir/$svc-$port.txt") host(s) on port $port -> $svc/$svc-$port.txt"
  done < <(cut -f2 "$pairs" | sort -un)
  return 0
}

prep_passlist() { # <svc> <dir> -> echoes path
  local svc="$1" dir="$2"
  local src="$SECLISTS_DIR/${svc}-betterdefaultpasslist.txt"
  local dst="$dir/${svc}-betterdefaultpasslist.txt"
  if [[ ! -r "$src" ]]; then
    warn "$svc: missing $src - skipping credential run"
    return 1
  fi
  cp -f "$src" "$dst"
  sed -i 's/:/ /' "$dst"          # step 4: first colon only
  awk -v skip="$dst.skipped" '{ if (NF >= 2) print; else print > skip }' "$dst" > "$dst.tmp" \
    && mv "$dst.tmp" "$dst"
  [[ -s "$dst.skipped" ]] && warn "$svc: $(wc -l < "$dst.skipped") malformed passlist line(s) dropped"
  printf '%s\n' "$dst"
}

# --------------------------------------------------------------------------- #
# Runners
# --------------------------------------------------------------------------- #
msf_run() { # <dir> <console-log-basename> <command string> [cap-seconds]
  local dir="$1" lg="$2" cmd="$3" cap="${4:-$MSF_TIMEOUT}" rc=0
  local -a pre=()
  # --kill-after: msfconsole ignores SIGTERM while ruby is inside a blocking
  # socket read, so follow up with SIGKILL 30s later or it never dies.
  [[ "$cap" =~ ^[1-9][0-9]*$ ]] && pre=(timeout --foreground --kill-after=30s "${cap}s")
  logcmd "$dir" "${pre[*]:-} msfconsole -qx '$cmd'"
  if [[ $DRYRUN -eq 1 ]]; then
    printf '  (dry-run) cd %q && %s msfconsole -qx %q\n' "$dir" "${pre[*]:-}" "$cmd"; return 0
  fi
  command -v msfconsole >/dev/null || { warn "msfconsole missing; skipped"; return 1; }
  ( cd "$dir" && "${pre[@]}" msfconsole -qx "$cmd" ) > "$dir/$lg" 2>&1
  rc=$?
  if [[ $rc -eq 124 || $rc -eq 137 ]]; then
    warn "$lg: killed at the ${cap}s wall-clock cap - results are PARTIAL (raise -M / MSF_TIMEOUT_*, or lower -m / -g)"
    _rlog "TIMEOUT $lg cap=${cap}s rc=$rc"
  fi
  return 0
}

nmap_run() { # <dir> <args...>
  local dir="$1"; shift
  logcmd "$dir" "nmap $*"
  if [[ $DRYRUN -eq 1 ]]; then
    printf '  (dry-run) cd %q && nmap %s\n' "$dir" "$*"; return 0
  fi
  command -v nmap >/dev/null || { warn "nmap missing; skipped"; return 1; }
  ( cd "$dir" && nmap "$@" >/dev/null 2>&1 )
}

run_msf_login() { # <svc> <module> <dir> <hostfile> <port> <passlist>
  local svc="$1" mod="$2" dir="$3" hf="$4" port="$5" pl="$6"
  local extra="set ConnectTimeout ${CONNECT_TIMEOUT} ; "
  case "$svc" in
    # SSH_TIMEOUT caps KEX+auth negotiation (msf default 30). ConnectTimeout
    # does NOT cover this - ssh_login goes through Net::SSH, not the TCP mixin.
    ssh)    extra+="set SSH_TIMEOUT ${CONNECT_TIMEOUT} ; "
            extra+="set CreateSession ${MSF_CREATE_SESSION} ; " ;;
    # TIMEOUT caps banner read + prompt waits (msf default 25). This is the
    # single biggest telnet time sink: dead-but-listening hosts burn it fully.
    telnet) extra+="set TIMEOUT ${CONNECT_TIMEOUT} ; "
            extra+="set CreateSession ${MSF_CREATE_SESSION} ; " ;;
  esac
  extra+="$(msf_brute_opts)"
  # Absolute paths so the command also works in a batched console (no per-module cd).
  local hf_abs="$dir/$hf" pl_abs="$dir/$pl" spool_abs="$dir/${svc}-${port}-defaultpass.txt"
  local cmd="use auxiliary/scanner/${mod} ; set RHOSTS file:${hf_abs} ; set RPORT ${port} ; set USERPASS_FILE ${pl_abs} ; set USER_AS_PASS true ; set BLANK_PASSWORDS true ; set THREADS ${THREADS} ; ${extra}spool ${spool_abs} ; run"
  if [[ $MSF_BATCH -eq 1 ]]; then
    [[ $DRYRUN -eq 0 ]] && log "$svc: queued msf login on port $port ($(wc -l < "$dir/$hf") hosts)"
    printf '%s\n' "$cmd" >> "$BATCH_RC"
    return 0
  fi
  [[ $DRYRUN -eq 0 ]] && log "$svc: msf login scan on port $port ($(wc -l < "$dir/$hf") hosts, cap $(msf_cap_for "$svc")s)"
  msf_run "$dir" "${svc}-${port}-console.log" "$cmd ; exit -y" "$(msf_cap_for "$svc")"
}

# Run every queued Phase-2/3 login module in ONE msfconsole, then parse each
# module's spool and emit the per-service summary lines (deferred from the loop).
msf_batch_flush() {
  [[ $MSF_BATCH -eq 1 ]] || return 0
  [[ -s "${BATCH_RC:-}" ]] || return 0
  printf 'exit -y\n' >> "$BATCH_RC"
  local n="${#BATCH_ITEMS[@]}" cap=0 lg
  lg="$OUTDIR/$(basename "$BATCH_RC" .rc)-console.log"
  [[ "$MSF_TIMEOUT" =~ ^[1-9][0-9]*$ ]] && cap=$(( MSF_TIMEOUT * (n > 0 ? n : 1) ))
  logcmd "$OUTDIR" "msfconsole -q -r $BATCH_RC  (batched, $n modules, cap ${cap}s)"
  if [[ $DRYRUN -eq 1 ]]; then
    printf '  (dry-run) batched msfconsole -q -r %q (%s modules):\n' "$BATCH_RC" "$n"
    sed 's/^/      /' "$BATCH_RC"
    : > "$BATCH_RC"; BATCH_ITEMS=(); return 0
  fi
  if command -v msfconsole >/dev/null; then
    log "msf: running $n batched login module(s) in one console (cap ${cap}s)"
    local -a pre=()
    [[ "$cap" =~ ^[1-9][0-9]*$ ]] && pre=(timeout --foreground --kill-after=30s "${cap}s")
    ( "${pre[@]}" msfconsole -q -r "$BATCH_RC" ) > "$lg" 2>&1
    local rc=$?
    [[ $rc -eq 124 || $rc -eq 137 ]] && warn "batched msf run killed at ${cap}s cap - results are PARTIAL"
  else
    warn "msfconsole missing; batched run skipped"
  fi
  local it dir spool svc port aff lbl
  declare -A _lbl
  for it in "${BATCH_ITEMS[@]}"; do
    IFS='|' read -r dir spool svc port aff lbl <<<"$it"
    msf_hits "$spool" >> "$aff"
    record_msf_creds "$spool" "$svc" "$port"
    _lbl["$aff"]="$lbl"
  done
  for aff in "${!_lbl[@]}"; do
    dedupe_file "$aff"
    printf '%-22s : %s host(s)\n' "${_lbl[$aff]}" "$(wc -l < "$aff")" >> "$SUMMARY"
  done
  : > "$BATCH_RC"; BATCH_ITEMS=()
}

msf_success_lines() {
  [[ -r "$1" ]] || return 0
  strip_ansi < "$1" 2>/dev/null | grep -Ei '^\[\+\].*success'
}
# Capture the host from an msf "[+] host:port" line - IPv4 or bracketed IPv6.
msf_hits() { msf_success_lines "$1" | sed -nE 's/^\[\+\][[:space:]]*\[?([0-9A-Fa-f:.]+)\]?:[0-9].*/\1/p' ; }

# HEURISTIC credential extraction - msf output format varies per module/version.
record_msf_creds() { # <spoolfile> <service> <port>
  local f="$1" svc="$2" port="$3" line ip cred user pass
  [[ -r "$f" ]] || return 0
  while IFS= read -r line; do
    ip="$(sed -nE 's/^\[\+\][[:space:]]*\[?([0-9A-Fa-f:.]+)\]?:[0-9].*/\1/p' <<<"$line")"
    [[ -n "$ip" ]] || continue
    cred="$(sed -E 's/^.*[Ss]uccess(ful)?:[[:space:]]*//' <<<"$line")"
    cred="${cred#\'}"; cred="${cred%%\'*}"; cred="${cred%% *}"; cred="${cred%%@*}"
    user="${cred%%:*}"; pass="${cred#*:}"
    [[ "$pass" == "$cred" ]] && pass=""
    add_finding "$ip" "$port" "$svc" "default/weak credentials" \
                "$user" "$pass" "" "${f#$OUTDIR/}"
  done < <(msf_success_lines "$f")
}

nmap_script_hits() { # <.nmap file> <egrep pattern>
  local f="$1" pat="$2"
  [[ -r "$f" ]] || return 0
  awk -v pat="$pat" '
    /^Nmap scan report for/ { ip=$NF; gsub(/[()]/,"",ip) }
    $0 ~ pat { if (ip != "") print ip }
  ' "$f"
}

# Generic Phase-1 NSE check for the simple one-finding services: build the host
# list, run one --script set per port, and flag every host whose .nmap output
# matches <pat>. Writes affected.txt + one summary line.
simple_nse_check() { # <svc> <defport> <svc_re> <nmap-script> <pat> <finding> <label> [heuristic]
  local svc="$1" defport="$2" re="$3" script="$4" pat="$5" finding="$6" label="$7" heur="${8:-}"
  local dir="$OUTDIR/$svc"; mkdir -p "$dir"; : > "$dir/affected.txt"
  local hf base port ip
  if build_hostlists "$svc" "$defport" "$re" "$dir"; then
    for hf in "$dir/$svc"-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^${svc}-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" --script "$script" \
               -iL "$base" -oA "$svc-$port"
      [[ $DRYRUN -eq 0 ]] || continue
      nmap_script_hits "$dir/$svc-$port.nmap" "$pat" | dedupe_hosts >> "$dir/affected.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "$port" "$svc" "$finding" "" "" "" "$svc/$svc-$port.nmap"
      done < <(nmap_script_hits "$dir/$svc-$port.nmap" "$pat" | dedupe_hosts)
    done
    dedupe_file "$dir/affected.txt"
  else
    warn "$svc: no hosts found"
  fi
  printf '%-22s : %s host(s)%s\n' "$label" "$(wc -l < "$dir/affected.txt")" "${heur:+  [HEURISTIC]}" >> "$SUMMARY"
}

# Redis AUTH takes a bare password (no username pre-6.0), so it needs a
# PASS_FILE, not the user:pass USERPASS_FILE format. Order of preference:
#   1. $REDIS_PASS_FILE if set
#   2. a redis-betterdefaultpasslist.txt in SecLists, if one ever ships
#   3. SecLists top-100 common passwords
#   4. built-in fallback list written into the redis/ folder
prep_redis_passlist() { # <dir> -> echoes path
  local dir="$1" dst="$dir/redis-passwords.txt" src=""
  local -a cands=(
    "${REDIS_PASS_FILE:-}"
    "$SECLISTS_DIR/redis-betterdefaultpasslist.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
  )
  for c in "${cands[@]}"; do
    [[ -n "$c" && -r "$c" ]] && { src="$c"; break; }
  done
  if [[ -n "$src" ]]; then
    # strip any user: prefix so the file is pure passwords
    sed -E 's/^[^:]*://' "$src" | grep -v '^[[:space:]]*$' | sort -u > "$dst"
    log "redis: password list from $src ($(wc -l < "$dst") entries)"
  else
    printf '%s\n' foobared redis redis123 password Password1 admin default \
                  changeme root 123456 secret pass > "$dst"
    warn "redis: no wordlist found, using built-in $(wc -l < "$dst")-entry fallback (set REDIS_PASS_FILE)"
  fi
  printf '%s\n' "$dst"
}

# redis_login prints a bare password, not user:pass - parse it separately.
record_redis_creds() { # <spoolfile> <port>
  local f="$1" port="$2" line ip cred user pass
  [[ -r "$f" ]] || return 0
  while IFS= read -r line; do
    ip="$(sed -nE 's/^\[\+\][[:space:]]*\[?([0-9A-Fa-f:.]+)\]?:[0-9].*/\1/p' <<<"$line")"
    [[ -n "$ip" ]] || continue
    cred="$(sed -E 's/^.*[Ss]uccess(ful)?:[[:space:]]*//' <<<"$line")"
    cred="${cred#\'}"; cred="${cred%%\'*}"
    if [[ "$cred" == *:* ]]; then user="${cred%%:*}"; pass="${cred#*:}"
    else user=""; pass="$cred"; fi
    add_finding "$ip" "$port" "redis" "weak/default AUTH password" \
                "$user" "$pass" "read-write" "${f#$OUTDIR/}"
  done < <(msf_success_lines "$f")
}

# VNC auth is password-only (no username). Prep a pure-password list from the
# SecLists vnc-betterdefaultpasslist, stripping any user: prefix if present.
prep_vnc_passlist() { # <dir> -> echoes path
  local dir="$1" src="$SECLISTS_DIR/vnc-betterdefaultpasslist.txt" dst="$dir/vnc-passwords.txt"
  if [[ ! -r "$src" ]]; then
    warn "vnc: missing $src - skipping vnc_login"
    return 1
  fi
  sed -E 's/^[^:]*://' "$src" | grep -v '^[[:space:]]*$' | sort -u > "$dst"
  log "vnc: password list from $src ($(wc -l < "$dst") entries)"
  printf '%s\n' "$dst"
}

# vnc_login prints a bare password, not user:pass - parse it separately.
record_vnc_creds() { # <spoolfile> <port>
  local f="$1" port="$2" line ip cred
  [[ -r "$f" ]] || return 0
  while IFS= read -r line; do
    ip="$(sed -nE 's/^\[\+\][[:space:]]*\[?([0-9A-Fa-f:.]+)\]?:[0-9].*/\1/p' <<<"$line")"
    [[ -n "$ip" ]] || continue
    cred="$(sed -E 's/^.*[Ss]uccess(ful)?:[[:space:]]*//' <<<"$line")"
    cred="${cred#\'}"; cred="${cred%%\'*}"; cred="${cred#:}"
    add_finding "$ip" "$port" "vnc" "weak/default VNC password" "" "$cred" "" "${f#$OUTDIR/}"
  done < <(msf_success_lines "$f")
}

# Does an NFS export's client list allow anyone to mount?
# Input: the client field of a showmount -e line (may be comma/space separated).
# Public markers: bare '*', 'everyone', '(everyone)', 'all', 0.0.0.0/0, ::/0,
# or an empty client field (no restriction listed).
# Deliberately does NOT match '*.example.com' or '10.0.0.0/8'.
is_public_client() {
  local raw="${1:-}" tok
  [[ -z "${raw//[[:space:]]/}" ]] && return 0
  local -a toks
  IFS=$', \t' read -r -a toks <<<"$raw"
  for tok in "${toks[@]}"; do
    [[ -n "$tok" ]] || continue
    tok="${tok#\(}"; tok="${tok%\)}"   # (everyone) -> everyone
    tok="${tok%%(*}"                   # *(rw)      -> *
    case "${tok,,}" in
      '*'|everyone|all|world|'<world>'|'0.0.0.0/0'|'0.0.0.0'|'::/0'|'::') return 0 ;;
    esac
  done
  return 1
}

# --------------------------------------------------------------------------- #
# Cleartext-protocol finding (FTP / Telnet)
# --------------------------------------------------------------------------- #
# FTP and Telnet carry credentials in cleartext. Flag that as a finding in its
# own right - but ONLY where the TCP *service* scan (-T) positively identified
# the protocol by name. A port scan alone cannot confirm what is listening, so
# a bare open-port match is not enough.
confirmed_by_svcscan() { # <svc_name_regex> -> "ip<TAB>port" per confirmed host
  awk -F'\t' -v re="$1" '$4 ~ /^open/ && $5 ~ re {print $1"\t"$2}' "$TCP_SVC_TSV" | sort -u
}

record_cleartext() { # <svc> <svc_name_regex> <dir>
  local svc="$1" re="$2" dir="$3" ip port
  local out="$dir/affected-cleartext.txt"; : > "$out"
  while IFS=$'\t' read -r ip port; do
    [[ -n "$ip" ]] || continue
    echo "$ip" >> "$out"
    [[ $DRYRUN -eq 0 ]] && add_finding "$ip" "$port" "$svc" \
      "cleartext authentication protocol" "" "" "" "service scan confirmed $svc on port $port"
  done < <(confirmed_by_svcscan "$re")
  dedupe_file "$out"
  printf '%-22s : %s host(s)\n' "$svc cleartext" "$(wc -l < "$out")" >> "$SUMMARY"
}

# --------------------------------------------------------------------------- #
# SSH weak crypto + SSHv1 (cheap NSE - runs in Phase 1)
# --------------------------------------------------------------------------- #
# ssh2-enum-algos only *lists* the offered algorithms; we judge weak/strong
# against the SSH_WEAK_* denylists here. SSHv1 is flagged from the sshv1 script
# OR a '(protocol 1.x)' banner (1.99 = still allows v1 alongside v2).
ssh_crypto_audit() {
  local dir="$OUTDIR/ssh"; mkdir -p "$dir"
  : > "$dir/affected-weakalgos.txt"; : > "$dir/affected-sshv1.txt"
  if ! build_hostlists "ssh" "22" "^ssh$" "$dir"; then
    warn "ssh: no hosts for crypto audit"
    printf '%-22s : %s host(s)\n' "ssh weak-algos" 0 >> "$SUMMARY"
    printf '%-22s : %s host(s)\n' "ssh sshv1"      0 >> "$SUMMARY"
    return 0
  fi
  local hf base port nmapf key ip cat algo re lbl
  for hf in "$dir"/ssh-*.txt; do
    base="$(basename "$hf")"
    [[ "$base" =~ ^ssh-([0-9]+)\.txt$ ]] || continue
    port="${BASH_REMATCH[1]}"
    nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -sV -p "$port" \
             --script ssh2-enum-algos,sshv1 -iL "$base" -oA "ssh-algos-$port"
    [[ $DRYRUN -eq 0 ]] || continue
    nmapf="$dir/ssh-algos-$port.nmap"
    [[ -r "$nmapf" ]] || continue

    # weak algorithms, grouped one finding per host per category
    unset weak; declare -A weak
    while IFS=$'\t' read -r ip cat algo; do
      case "$cat" in
        kex_algorithms)             re="$SSH_WEAK_KEX";     lbl="key exchange" ;;
        server_host_key_algorithms) re="$SSH_WEAK_HOSTKEY"; lbl="host key" ;;
        encryption_algorithms)      re="$SSH_WEAK_CIPHER";  lbl="cipher" ;;
        mac_algorithms)             re="$SSH_WEAK_MAC";     lbl="MAC" ;;
        *) continue ;;
      esac
      grep -qE -- "$re" <<<"$algo" || continue
      key="$ip|$lbl"
      weak["$key"]+="${weak[$key]:+, }$algo"
    done < <(awk -v OFS='\t' '
      function clean(s){ sub(/^[[:space:]]*\|_?[[:space:]]*/, "", s); return s }
      /^Nmap scan report for/ { ip=$NF; gsub(/[()]/, "", ip); cat=""; next }
      /^\|/ {
        c = clean($0)
        if (c ~ /^(kex_algorithms|server_host_key_algorithms|encryption_algorithms|mac_algorithms|compression_algorithms):/) {
          cat=c; sub(/:.*/, "", cat); next
        }
        if (cat != "" && ip != "" && c ~ /^[A-Za-z0-9]/) { sub(/[[:space:]].*$/, "", c); if (c != "") print ip, cat, c }
        next
      }
      { cat="" }
    ' "$nmapf")

    for key in "${!weak[@]}"; do
      ip="${key%%|*}"; lbl="${key#*|}"
      echo "$ip" >> "$dir/affected-weakalgos.txt"
      add_finding "$ip" "$port" "ssh" "weak SSH $lbl offered: ${weak[$key]}" \
                  "" "" "" "ssh/ssh-algos-$port.nmap"
    done

    # SSHv1: sshv1 script hit OR a 'protocol 1.x' banner from -sV
    {
      nmap_script_hits "$nmapf" "supports SSHv1"
      awk '/^Nmap scan report for/ { ip=$NF; gsub(/[()]/, "", ip) }
           /^[0-9]+\/tcp.*ssh.*\(protocol 1\./ { if (ip) print ip }' "$nmapf"
    } | dedupe_hosts > "$dir/.sshv1-$port"
    while read -r ip; do
      [[ -n "$ip" ]] || continue
      echo "$ip" >> "$dir/affected-sshv1.txt"
      add_finding "$ip" "$port" "ssh" "SSHv1 (protocol 1) supported" "" "" "" "ssh/ssh-algos-$port.nmap"
    done < "$dir/.sshv1-$port"
    rm -f "$dir/.sshv1-$port"
  done
  dedupe_file "$dir/affected-weakalgos.txt"
  dedupe_file "$dir/affected-sshv1.txt"
  printf '%-22s : %s host(s)\n' "ssh weak-algos" "$(wc -l < "$dir/affected-weakalgos.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "ssh sshv1"      "$(wc -l < "$dir/affected-sshv1.txt")"      >> "$SUMMARY"
}

# --------------------------------------------------------------------------- #
# TCP credential services (definition only - called by the dispatcher)
# --------------------------------------------------------------------------- #
# run_tcp_creds <svc-name>...  - cleartext flag first (ftp/telnet), then creds.
run_tcp_creds() {
  local e entry svc mod defport re dir passlist pl_base hf base port target aip name
  for name in "$@"; do
    entry=""
    for e in "${SERVICES[@]}"; do [[ "${e%%|*}" == "$name" ]] && { entry="$e"; break; }; done
    [[ -n "$entry" ]] || { warn "run_tcp_creds: unknown service '$name'"; continue; }
  IFS='|' read -r svc mod defport re <<< "$entry"
  want "$svc" || continue

  dir="$OUTDIR/$svc"; mkdir -p "$dir"
  case "$svc" in ftp|telnet) record_cleartext "$svc" "$re" "$dir" ;; esac
  if ! build_hostlists "$svc" "$defport" "$re" "$dir"; then
    warn "$svc: no hosts found"
    if [[ "$svc" == "ftp" ]]; then : > "$dir/affected-defaultpass.txt"; : > "$dir/affected-anonymous.txt"
    else : > "$dir/affected.txt"; fi
    continue
  fi

  passlist="$(prep_passlist "$svc" "$dir")" || passlist=""
  pl_base="$(basename "${passlist:-}")"

  # ---- FTP: anonymous first, then exclude anon hosts from bruteforce ----
  if [[ "$svc" == "ftp" ]]; then
    : > "$dir/affected-anonymous.txt"; : > "$dir/affected-defaultpass.txt"
    for hf in "$dir"/ftp-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^ftp-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"

      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" --script ftp-anon \
               -iL "$base" -oA "ftp-anon-$port"
      if [[ $DRYRUN -eq 0 ]]; then
        nmap_script_hits "$dir/ftp-anon-$port.nmap" "Anonymous FTP login allowed" \
          | dedupe_hosts >> "$dir/affected-anonymous.txt"
        dedupe_file "$dir/affected-anonymous.txt"
        while read -r aip; do
          [[ -n "$aip" ]] && add_finding "$aip" "$port" "ftp" "anonymous login allowed" \
            "anonymous" "" "" "ftp/ftp-anon-$port.nmap"
        done < <(nmap_script_hits "$dir/ftp-anon-$port.nmap" "Anonymous FTP login allowed" | dedupe_hosts)
      fi

      target="$base"
      if [[ -s "$dir/affected-anonymous.txt" ]]; then
        grep -vxF -f "$dir/affected-anonymous.txt" "$hf" > "$dir/ftp-${port}-noanon.txt" 2>/dev/null \
          || : > "$dir/ftp-${port}-noanon.txt"
        target="ftp-${port}-noanon.txt"
        log "ftp: port $port -> $(wc -l < "$dir/$target") non-anonymous host(s) for credential run"
      fi

      [[ -s "$dir/$target" ]] || { warn "ftp: no hosts left on port $port after anon exclusion"; continue; }
      [[ -n "$pl_base" ]] || continue
      run_msf_login "$svc" "$mod" "$dir" "$target" "$port" "$pl_base"
      if [[ $MSF_BATCH -eq 1 ]]; then
        BATCH_ITEMS+=("$dir|$dir/ftp-${port}-defaultpass.txt|ftp|$port|$dir/affected-defaultpass.txt|ftp defaultpass")
      else
        msf_hits "$dir/ftp-${port}-defaultpass.txt" >> "$dir/affected-defaultpass.txt"
        record_msf_creds "$dir/ftp-${port}-defaultpass.txt" "ftp" "$port"
      fi
    done
    dedupe_file "$dir/affected-anonymous.txt"
    printf '%-22s : %s host(s)\n' "ftp anonymous"   "$(wc -l < "$dir/affected-anonymous.txt")"   >> "$SUMMARY"
    if [[ $MSF_BATCH -eq 0 ]]; then
      dedupe_file "$dir/affected-defaultpass.txt"
      printf '%-22s : %s host(s)\n' "ftp defaultpass" "$(wc -l < "$dir/affected-defaultpass.txt")" >> "$SUMMARY"
    fi
    continue
  fi

  # ---- everything else ----
  : > "$dir/affected.txt"
  for hf in "$dir/$svc"-*.txt; do
    base="$(basename "$hf")"
    [[ "$base" =~ ^${svc}-([0-9]+)\.txt$ ]] || continue
    port="${BASH_REMATCH[1]}"
    [[ -n "$pl_base" ]] || continue
    run_msf_login "$svc" "$mod" "$dir" "$base" "$port" "$pl_base"
    if [[ $MSF_BATCH -eq 1 ]]; then
      BATCH_ITEMS+=("$dir|$dir/${svc}-${port}-defaultpass.txt|$svc|$port|$dir/affected.txt|$svc")
    else
      msf_hits "$dir/${svc}-${port}-defaultpass.txt" >> "$dir/affected.txt"
      record_msf_creds "$dir/${svc}-${port}-defaultpass.txt" "$svc" "$port"
    fi
  done
  if [[ $MSF_BATCH -eq 0 ]]; then
    dedupe_file "$dir/affected.txt"
    printf '%-22s : %s host(s)\n' "$svc" "$(wc -l < "$dir/affected.txt")" >> "$SUMMARY"
  fi
  done
}


# --------------------------------------------------------------------------- #
# PHASE 1: nmap-led + cheap probes
#   nmap NSE scans are bounded by --host-timeout; showmount and the
#   redis/snmp probes are one or a few connects per host.
# --------------------------------------------------------------------------- #
phase "PHASE 1: enumeration + unauth / anon / weak-config checks"

# --------------------------------------------------------------------------- #
# NFS (showmount -e)
# --------------------------------------------------------------------------- #
if want nfs; then
  dir="$OUTDIR/nfs"; mkdir -p "$dir"
  : > "$dir/affected-showmount.txt"; : > "$dir/affected-public.txt"
  if build_hostlists "nfs" "$NFS_PORT" "$NFS_RE" "$dir"; then
    for hf in "$dir"/nfs-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^nfs-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"

      # nmap scripts first - bounded by --host-timeout, and they also give the
      # mount-permission detail showmount does not.
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" \
               --script nfs-showmount,nfs-statfs -iL "$base" -oA "nfs-scripts-$port"

      out="$dir/showmount-${port}.txt"
      logcmd "$dir" "for ip in \$(cat $base): timeout ${CONNECT_TIMEOUT}s showmount -e \$ip"
      if [[ $DRYRUN -eq 1 ]]; then
        printf '  (dry-run) cd %q && timeout %ss showmount -e <each host in %s>\n' \
               "$dir" "$CONNECT_TIMEOUT" "$base"
      elif ! command -v showmount >/dev/null; then
        warn "showmount missing (apt install nfs-common)"
      else
        : > "$out"
        log "nfs: showmount -e against $(wc -l < "$hf") host(s), ${CONNECT_TIMEOUT}s each"
        while read -r ip; do
          [[ -n "$ip" ]] || continue
          printf '===== %s =====\n' "$ip" >> "$out"
          res="$(timeout --foreground "${CONNECT_TIMEOUT}s" showmount -e "$ip" 2>&1)"
          printf '%s\n' "$res" >> "$out"
          exports="$(sed '1d' <<<"$res" | grep -E '^/' || true)"
          [[ -n "$exports" ]] || continue

          # export list was disclosed
          echo "$ip" >> "$dir/affected-showmount.txt"
          host_public=0
          while IFS= read -r ex; do
            [[ -n "$ex" ]] || continue
            path="${ex%%[[:space:]]*}"
            clients="$(sed -E 's/^[^[:space:]]+[[:space:]]*//' <<<"$ex")"
            if is_public_client "$clients"; then
              host_public=1
              add_finding "$ip" "$port" "nfs" "export mountable by everyone" \
                          "" "$path" "${clients:-<no client restriction listed>}" \
                          "nfs/showmount-${port}.txt"
            else
              add_finding "$ip" "$port" "nfs" "export list disclosed via showmount" \
                          "" "$path" "$clients" "nfs/showmount-${port}.txt"
            fi
          done <<<"$exports"
          [[ $host_public -eq 1 ]] && echo "$ip" >> "$dir/affected-public.txt"
        done < "$hf"
      fi
    done
    dedupe_file "$dir/affected-showmount.txt"
    dedupe_file "$dir/affected-public.txt"
  else
    warn "nfs: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "nfs showmount"  "$(wc -l < "$dir/affected-showmount.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "nfs public mount" "$(wc -l < "$dir/affected-public.txt")"  >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# Redis (unauthenticated access + password brute force)
# --------------------------------------------------------------------------- #
if want redis; then
  dir="$OUTDIR/redis"; mkdir -p "$dir"
  : > "$dir/affected-unauth.txt"; : > "$dir/affected-defaultpass.txt"
  if build_hostlists "redis" "$REDIS_PORT" "$REDIS_RE" "$dir"; then
    pw="$(prep_redis_passlist "$dir")"; pw_base="$(basename "$pw")"
    for hf in "$dir"/redis-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^redis-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"

      # 1) nmap redis-info first (bounded by --host-timeout)
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" --script redis-info \
               -iL "$base" -oA "redis-info-$port"

      # 2) msf redis_server - INFO only succeeds when no AUTH is required
      cmd="use auxiliary/scanner/redis/redis_server ; set RHOSTS file:${base} ; set RPORT ${port} ; set THREADS ${THREADS} ; set ConnectTimeout ${CONNECT_TIMEOUT} ; spool redis-${port}-unauth.txt ; run ; exit -y"
      [[ $DRYRUN -eq 0 ]] && log "redis: msf redis_server on port $port"
      msf_run "$dir" "redis-${port}-server-console.log" "$cmd"

      if [[ $DRYRUN -eq 0 ]]; then
        {
          strip_ansi < "$dir/redis-${port}-unauth.txt" 2>/dev/null \
            | grep -E '^\[\+\]' | grep -Evi 'noauth|auth required|requirepass' \
            | sed -nE 's/^\[\+\][[:space:]]*([0-9.]+):.*/\1/p'
          nmap_script_hits "$dir/redis-info-$port.nmap" "redis_version|Version"
        } | dedupe_hosts > "$dir/.hits-$port"
        cat "$dir/.hits-$port" >> "$dir/affected-unauth.txt"
        while read -r ip; do
          [[ -n "$ip" ]] && add_finding "$ip" "$port" "redis" \
            "unauthenticated access (no AUTH)" "" "" "read-write" \
            "redis/redis-${port}-unauth.txt"
        done < "$dir/.hits-$port"
        rm -f "$dir/.hits-$port"
        dedupe_file "$dir/affected-unauth.txt"
      fi

      # 3) redis_login against hosts that actually require AUTH
      target="$base"
      if [[ $DRYRUN -eq 0 && -s "$dir/affected-unauth.txt" ]]; then
        grep -vxF -f "$dir/affected-unauth.txt" "$hf" > "$dir/redis-${port}-authreq.txt" 2>/dev/null \
          || : > "$dir/redis-${port}-authreq.txt"
        target="redis-${port}-authreq.txt"
        log "redis: port $port -> $(wc -l < "$dir/$target") host(s) requiring AUTH"
      fi
      [[ $DRYRUN -eq 1 || -s "$dir/$target" ]] || { warn "redis: no AUTH-required hosts on port $port"; continue; }
      [[ -n "$pw_base" ]] || { warn "redis: no password list available - skipping redis_login"; continue; }

      # Redis AUTH is password-only pre-6.0; BLANK_PASSWORDS off because a blank
      # password is the unauth case already covered above.
      cmd="use auxiliary/scanner/redis/redis_login ; set RHOSTS file:${target} ; set RPORT ${port} ; set PASS_FILE ${pw_base} ; set BLANK_PASSWORDS false ; set STOP_ON_SUCCESS false ; set THREADS ${THREADS} ; set ConnectTimeout ${CONNECT_TIMEOUT} ; $(msf_brute_opts)spool redis-${port}-defaultpass.txt ; run ; exit -y"
      [[ $DRYRUN -eq 0 ]] && log "redis: msf redis_login on port $port"
      msf_run "$dir" "redis-${port}-login-console.log" "$cmd"
      msf_hits "$dir/redis-${port}-defaultpass.txt" >> "$dir/affected-defaultpass.txt"
      record_redis_creds "$dir/redis-${port}-defaultpass.txt" "$port"
    done
    dedupe_file "$dir/affected-unauth.txt"
    dedupe_file "$dir/affected-defaultpass.txt"
  else
    warn "redis: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "redis unauth"      "$(wc -l < "$dir/affected-unauth.txt")"      >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "redis defaultpass" "$(wc -l < "$dir/affected-defaultpass.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# SNMP (UDP 161) - nmap snmp-brute + msf snmp_login for RO/RW split
# --------------------------------------------------------------------------- #
if want snmp; then
  dir="$OUTDIR/snmp"; mkdir -p "$dir"
  : > "$dir/affected-readonly.txt"; : > "$dir/affected-readwrite.txt"; : > "$dir/affected.txt"
  : > "$dir/affected-cleartext.txt"; : > "$dir/.comms"
  {
    awk -F'\t' '$2=="161" {print $1}' "$UDP_TSV"
    for l in "${SNMP_LISTS[@]}"; do
      grep -oE '^[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*$' "$l" | tr -d '[:blank:]'
    done
  } | dedupe_hosts > "$dir/snmp-161.txt"
  check_hostnames "$dir/snmp-161.txt" "snmp/snmp-161.txt"

  if [[ -s "$dir/snmp-161.txt" ]]; then
    ok "snmp: $(wc -l < "$dir/snmp-161.txt") host(s) -> snmp/snmp-161.txt"

    nmap_run "$dir" -Pn -sU "${NMAP_TO[@]}" $NMAP_EXTRA -p 161 --script snmp-brute \
             -iL snmp-161.txt -oA snmp-brute

    cmd="use auxiliary/scanner/snmp/snmp_login ; set RHOSTS file:snmp-161.txt ; set RPORT 161 ; set THREADS ${THREADS} ; set ConnectTimeout ${CONNECT_TIMEOUT} ; $(msf_brute_opts)set STOP_ON_SUCCESS false ; spool snmp-161-login.txt ; run ; exit -y"
    [[ $DRYRUN -eq 0 ]] && log "snmp: msf snmp_login (read-only / read-write classification)"
    msf_run "$dir" "snmp-161-console.log" "$cmd"

    if [[ $DRYRUN -eq 0 ]]; then
      # [+] 10.0.0.1:161 - Login Successful: public (Access level: read-only); Proof ...
      while IFS='|' read -r ip port comm access; do
        [[ -n "$ip" ]] || continue
        printf '%s\t%s\n' "$ip" "$comm" >> "$dir/.comms"
        case "$access" in
          *read-write*|*read_write*|*READ-WRITE*|*rw*)
            echo "$ip" >> "$dir/affected-readwrite.txt"
            add_finding "$ip" "$port" "snmp" "weak community string" "" "$comm" "read-write" \
                        "snmp/snmp-161-login.txt" ;;
          *)
            echo "$ip" >> "$dir/affected-readonly.txt"
            add_finding "$ip" "$port" "snmp" "weak community string" "" "$comm" \
                        "${access:-read-only (assumed)}" "snmp/snmp-161-login.txt" ;;
        esac
      done < <(strip_ansi < "$dir/snmp-161-login.txt" 2>/dev/null \
                | grep -Ei '^\[\+\].*success' \
                | sed -nE "s/^\[\+\][[:space:]]*([0-9.]+):([0-9]+).*[Ss]uccess(ful)?:[[:space:]]*'?([^' (;]+)'?[[:space:]]*(\(Access level:[[:space:]]*([^)]*)\))?.*/\1|\2|\4|\6/p")

      # hosts nmap found but msf did not (community outside msf's wordlist)
      comm -13 <(sort -u "$dir/affected-readonly.txt" "$dir/affected-readwrite.txt") \
               <(nmap_script_hits "$dir/snmp-brute.nmap" "Valid credentials" | sort -u) \
        >> "$dir/affected-readonly.txt"

      dedupe_file "$dir/affected-readonly.txt"
      dedupe_file "$dir/affected-readwrite.txt"
      # RW hosts are implicitly RO; keep the lists disjoint
      if [[ -s "$dir/affected-readwrite.txt" ]]; then
        grep -vxF -f "$dir/affected-readwrite.txt" "$dir/affected-readonly.txt" \
          > "$dir/.ro.tmp" 2>/dev/null || : > "$dir/.ro.tmp"
        mv "$dir/.ro.tmp" "$dir/affected-readonly.txt"
      fi
      cat "$dir/affected-readonly.txt" "$dir/affected-readwrite.txt" | dedupe_hosts > "$dir/affected.txt"

      # ---- Cleartext SNMP (v1 / v2c) ---------------------------------------
      # SNMPv1 and v2c both send the community string in cleartext (only v3
      # adds auth/privacy), so both are the same finding. The accurate test is
      # a direct GET with a community we already found: whichever version the
      # agent answers is enabled. Fall back to the Nmap service-scan version
      # string when net-snmp (snmpget) is unavailable.
      : > "$dir/snmp-cleartext-confirm.txt"
      # add the communities nmap's snmp-brute found (msf ones captured above)
      awk '
        /^Nmap scan report for/ { ip=$NF; gsub(/[()]/,"",ip) }
        /- *Valid credentials/ {
          c=$0; sub(/[[:space:]]*-[[:space:]]*Valid credentials.*/,"",c)
          sub(/^[|_[:space:]]+/,"",c)
          if (ip!="" && c!="") print ip"\t"c
        }' "$dir/snmp-brute.nmap" 2>/dev/null >> "$dir/.comms"

      if command -v snmpget >/dev/null; then
        sort -u "$dir/.comms" 2>/dev/null | while IFS=$'\t' read -r ip comm; do
          [[ -n "$ip" && -n "$comm" ]] || continue
          grep -qxF "$ip" "$dir/affected-cleartext.txt" 2>/dev/null && continue
          printf '===== %s (community: %s) =====\n' "$ip" "$comm" >> "$dir/snmp-cleartext-confirm.txt"
          vers=""
          for v in 1 2c; do
            if res="$(timeout --foreground "${CONNECT_TIMEOUT}s" \
                      snmpget -v"$v" -c "$comm" -r 0 -t "$CONNECT_TIMEOUT" -On \
                              "$ip" 1.3.6.1.2.1.1.1.0 2>&1)" && [[ -n "$res" ]]; then
              printf '[v%s] %s\n' "$v" "$res" >> "$dir/snmp-cleartext-confirm.txt"
              vers+="${vers:+, }v$v"
            fi
          done
          if [[ -n "$vers" ]]; then
            echo "$ip" >> "$dir/affected-cleartext.txt"
            add_finding "$ip" "161" "snmp" "cleartext SNMP community ($vers)" \
                        "" "$comm" "confirmed" "snmp/snmp-cleartext-confirm.txt"
          fi
        done
      else
        warn "snmp: snmpget not found (apt install snmp) - cleartext v1/v2c via version string only (heuristic)"
      fi

      # heuristic fallback: a UDP service scan that banners SNMPv1 / SNMPv2c
      while read -r ip; do
        [[ -n "$ip" ]] || continue
        grep -qxF "$ip" "$dir/affected-cleartext.txt" 2>/dev/null && continue
        echo "$ip" >> "$dir/affected-cleartext.txt"
        add_finding "$ip" "161" "snmp" "cleartext SNMP in service-scan version string (HEURISTIC - verify)" \
                    "" "" "" "service scan version string"
      done < <(awk -F'\t' '$2=="161" && $6 ~ /SNMPv1|SNMPv2/ {print $1}' "$UDP_TSV" | dedupe_hosts)

      dedupe_file "$dir/affected-cleartext.txt"
    fi
  else
    warn "snmp: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "snmp read-only"  "$(wc -l < "$dir/affected-readonly.txt")"  >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "snmp read-write" "$(wc -l < "$dir/affected-readwrite.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "snmp cleartext"  "$(wc -l < "$dir/affected-cleartext.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# TFTP (UDP 69)
# --------------------------------------------------------------------------- #
if want tftp; then
  dir="$OUTDIR/tftp"; mkdir -p "$dir"; : > "$dir/affected.txt"
  {
    awk -F'\t' '$2=="69" {print $1}' "$UDP_TSV"
    for l in "${TFTP_LISTS[@]}"; do
      grep -oE '^[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*$' "$l" | tr -d '[:blank:]'
    done
  } | dedupe_hosts > "$dir/tftp-69.txt"
  check_hostnames "$dir/tftp-69.txt" "tftp/tftp-69.txt"

  if [[ -s "$dir/tftp-69.txt" ]]; then
    ok "tftp: $(wc -l < "$dir/tftp-69.txt") host(s) -> tftp/tftp-69.txt"
    cmd="use auxiliary/scanner/tftp/tftpbrute ; set RHOSTS file:tftp-69.txt ; set THREADS ${THREADS} ; spool tftp-brute.txt ; run ; exit -y"
    [[ $DRYRUN -eq 0 ]] && log "tftp: msf tftpbrute"
    msf_run "$dir" "tftp-console.log" "$cmd"
    if [[ $DRYRUN -eq 0 ]]; then
      strip_ansi < "$dir/tftp-brute.txt" 2>/dev/null \
        | grep -E '^\[\+\]' \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | dedupe_hosts > "$dir/affected.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "69" "tftp" \
          "readable file via TFTP (HEURISTIC - verify)" "" "" "" "tftp/tftp-brute.txt"
      done < "$dir/affected.txt"
    fi
  else
    warn "tftp: no hosts found"
  fi
  printf '%-22s : %s host(s)  [HEURISTIC]\n' "tftp" "$(wc -l < "$dir/affected.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# Oracle (oscanner)
# --------------------------------------------------------------------------- #
if want oracle; then
  dir="$OUTDIR/oracle"; mkdir -p "$dir"; : > "$dir/affected.txt"
  if build_hostlists "oracle" "$ORACLE_PORT" "$ORACLE_RE" "$dir"; then
    for hf in "$dir"/oracle-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^oracle-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      args=(-f "$hf" -v)
      if [[ "$port" != "$ORACLE_PORT" ]]; then
        args=(-P "$port" -f "$hf" -v)
        warn "oracle: non-standard port $port; oscanner '-P' support is version-dependent"
      fi
      # oscanner has no per-host timeout: derive a whole-run cap from host count.
      cap=$(( CONNECT_TIMEOUT * ( $(wc -l < "$hf") + 1 ) * 4 ))
      # ...but never let a big host list turn into an open-ended run.
      [[ "$ORACLE_MAX_CAP" =~ ^[1-9][0-9]*$ && $cap -gt $ORACLE_MAX_CAP ]] && cap=$ORACLE_MAX_CAP
      logcmd "$dir" "timeout ${cap}s oscanner ${args[*]}"
      if [[ $DRYRUN -eq 1 ]]; then
        printf '  (dry-run) cd %q && timeout %ss oscanner %s\n' "$dir" "$cap" "${args[*]}"
      elif command -v oscanner >/dev/null; then
        log "oracle: oscanner on port $port (cap ${cap}s)"
        ( cd "$dir" && timeout --foreground "${cap}s" oscanner "${args[@]}" ) \
          > "$dir/oscanner-${port}.txt" 2>&1
        # HEURISTIC: oscanner output varies by version - verify manually.
        strip_ansi < "$dir/oscanner-${port}.txt" \
          | grep -Ei 'account|password|found|valid|sid' \
          | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' >> "$dir/affected.txt"
      else
        warn "oscanner not installed (apt install oscanner)"
      fi
    done
    dedupe_file "$dir/affected.txt"
    while read -r ip; do
      [[ -n "$ip" ]] && add_finding "$ip" "$ORACLE_PORT" "oracle" \
        "oscanner hit (HEURISTIC - verify)" "" "" "" "oracle/"
    done < "$dir/affected.txt"
  else
    warn "oracle: no hosts found"
  fi
  printf '%-22s : %s host(s)  [HEURISTIC]\n' "oracle" "$(wc -l < "$dir/affected.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# SSH weak crypto + SSHv1 (cheap NSE, no credential guessing)
# --------------------------------------------------------------------------- #
want ssh && ssh_crypto_audit

# --------------------------------------------------------------------------- #
# SMTP (open relay)
# --------------------------------------------------------------------------- #
if want smtp; then
  dir="$OUTDIR/smtp"; mkdir -p "$dir"; : > "$dir/affected-openrelay.txt"
  if build_hostlists "smtp" "$SMTP_PORT" "$SMTP_RE" "$dir"; then
    for hf in "$dir"/smtp-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^smtp-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      # NOTE: smtp-open-relay actually attempts to relay mail through the target.
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" --script smtp-open-relay \
               -iL "$base" -oA "smtp-open-relay-$port"
      if [[ $DRYRUN -eq 0 ]]; then
        nmap_script_hits "$dir/smtp-open-relay-$port.nmap" "is an open relay" \
          | dedupe_hosts >> "$dir/affected-openrelay.txt"
        while read -r ip; do
          [[ -n "$ip" ]] && add_finding "$ip" "$port" "smtp" "open mail relay" \
            "" "" "" "smtp/smtp-open-relay-$port.nmap"
        done < <(nmap_script_hits "$dir/smtp-open-relay-$port.nmap" "is an open relay" | dedupe_hosts)
      fi
    done
    dedupe_file "$dir/affected-openrelay.txt"
  else
    warn "smtp: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "smtp open-relay" "$(wc -l < "$dir/affected-openrelay.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# VNC (insecure security types + weak/missing password)
# --------------------------------------------------------------------------- #
if want vnc; then
  dir="$OUTDIR/vnc"; mkdir -p "$dir"
  : > "$dir/affected-noauth.txt"; : > "$dir/affected-weaksectype.txt"; : > "$dir/affected-defaultpass.txt"
  if build_hostlists "vnc" "$VNC_PORT" "$VNC_RE" "$dir"; then
    pw="$(prep_vnc_passlist "$dir")" || pw=""; pw_base="$(basename "${pw:-}")"
    for hf in "$dir"/vnc-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^vnc-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"

      # 1) security types via nmap vnc-info; flag None (no auth) and any type
      #    that is not modern (not Tight / VeNCrypt / RA2).
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" --script vnc-info \
               -iL "$base" -oA "vnc-info-$port"
      if [[ $DRYRUN -eq 0 && -r "$dir/vnc-info-$port.nmap" ]]; then
        while IFS=$'\t' read -r ip st; do
          [[ -n "$ip" ]] || continue
          num="$(sed -nE 's/.*\(([0-9]+)\)[[:space:]]*$/\1/p' <<<"$st")"
          name="$(sed -E 's/[[:space:]]*\([0-9]+\)[[:space:]]*$//' <<<"$st")"
          if [[ "$num" == "1" || "$name" =~ [Nn]one ]]; then
            echo "$ip" >> "$dir/affected-noauth.txt"
            add_finding "$ip" "$port" "vnc" "VNC no authentication (security type None)" \
                        "" "" "" "vnc/vnc-info-$port.nmap"
          elif [[ "$name" =~ ($VNC_MODERN_RE) ]]; then
            : # modern security type - not flagged
          else
            echo "$ip" >> "$dir/affected-weaksectype.txt"
            add_finding "$ip" "$port" "vnc" "insecure VNC security type: $name ($num)" \
                        "" "" "" "vnc/vnc-info-$port.nmap"
          fi
        done < <(awk '
          /^Nmap scan report for/ { ip=$NF; gsub(/[()]/, "", ip); insec=0 }
          /^\|/ {
            l=$0; sub(/^[[:space:]]*\|_?[[:space:]]*/, "", l)
            if (l ~ /^Security types:/) { insec=1; next }
            if (insec) { if (l ~ /\([0-9]+\)[[:space:]]*$/) print ip"\t"l; else insec=0 }
            next
          }
          { insec=0 }
        ' "$dir/vnc-info-$port.nmap")
      fi

      # 2) weak / missing password via msf vnc_login (BLANK_PASSWORDS catches
      #    hosts with no password set)
      if [[ -n "$pw_base" ]]; then
        cmd="use auxiliary/scanner/vnc/vnc_login ; set RHOSTS file:${base} ; set RPORT ${port} ; set PASS_FILE ${pw_base} ; set BLANK_PASSWORDS true ; set THREADS ${THREADS} ; set ConnectTimeout ${CONNECT_TIMEOUT} ; $(msf_brute_opts)spool vnc-${port}-defaultpass.txt ; run ; exit -y"
        [[ $DRYRUN -eq 0 ]] && log "vnc: msf vnc_login on port $port"
        msf_run "$dir" "vnc-${port}-login-console.log" "$cmd"
        msf_hits "$dir/vnc-${port}-defaultpass.txt" >> "$dir/affected-defaultpass.txt"
        record_vnc_creds "$dir/vnc-${port}-defaultpass.txt" "$port"
      fi
    done
    dedupe_file "$dir/affected-noauth.txt"
    dedupe_file "$dir/affected-weaksectype.txt"
    dedupe_file "$dir/affected-defaultpass.txt"
  else
    warn "vnc: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "vnc no-auth"      "$(wc -l < "$dir/affected-noauth.txt")"      >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "vnc weak-sectype" "$(wc -l < "$dir/affected-weaksectype.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "vnc defaultpass"  "$(wc -l < "$dir/affected-defaultpass.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# SMB (SMBv1 / signing not required / null session)
# --------------------------------------------------------------------------- #
# Config checks only - no credential spray (SMB/AD lockout risk).
if want smb; then
  dir="$OUTDIR/smb"; mkdir -p "$dir"
  : > "$dir/affected-smbv1.txt"; : > "$dir/affected-nosigning.txt"; : > "$dir/affected-nullsession.txt"
  if build_hostlists "smb" "$SMB_PORT" "$SMB_RE" "$dir"; then
    for hf in "$dir"/smb-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^smb-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" \
               --script smb-protocols,smb-security-mode,smb2-security-mode,smb-enum-shares \
               -iL "$base" -oA "smb-$port"
      [[ $DRYRUN -eq 0 ]] || continue
      f="$dir/smb-$port.nmap"
      nmap_script_hits "$f" "SMBv1|NT LM 0.12" | dedupe_hosts >> "$dir/affected-smbv1.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "$port" "smb" "SMBv1 enabled" "" "" "" "smb/smb-$port.nmap"
      done < <(nmap_script_hits "$f" "SMBv1|NT LM 0.12" | dedupe_hosts)
      nmap_script_hits "$f" "not required|signing disabled|Message signing disabled" | dedupe_hosts >> "$dir/affected-nosigning.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "$port" "smb" "SMB message signing not required" "" "" "" "smb/smb-$port.nmap"
      done < <(nmap_script_hits "$f" "not required|signing disabled|Message signing disabled" | dedupe_hosts)
      nmap_script_hits "$f" "Anonymous access:|<anonymous>|access: READ" | dedupe_hosts >> "$dir/affected-nullsession.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "$port" "smb" "null/anonymous SMB session" "" "" "" "smb/smb-$port.nmap"
      done < <(nmap_script_hits "$f" "Anonymous access:|<anonymous>|access: READ" | dedupe_hosts)
    done
    dedupe_file "$dir/affected-smbv1.txt"; dedupe_file "$dir/affected-nosigning.txt"; dedupe_file "$dir/affected-nullsession.txt"
  else
    warn "smb: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "smb smbv1"       "$(wc -l < "$dir/affected-smbv1.txt")"     >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "smb no-signing"  "$(wc -l < "$dir/affected-nosigning.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)  [HEURISTIC]\n' "smb null-session" "$(wc -l < "$dir/affected-nullsession.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# RDP (legacy security layer / NLA not enforced; optional BlueKeep)
# --------------------------------------------------------------------------- #
if want rdp; then
  dir="$OUTDIR/rdp"; mkdir -p "$dir"
  : > "$dir/affected-weaksec.txt"; : > "$dir/affected-bluekeep.txt"
  if build_hostlists "rdp" "$RDP_PORT" "$RDP_RE" "$dir"; then
    for hf in "$dir"/rdp-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^rdp-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" \
               --script rdp-enum-encryption,rdp-ntlm-info -iL "$base" -oA "rdp-$port"
      if [[ $DRYRUN -eq 0 ]]; then
        f="$dir/rdp-$port.nmap"
        nmap_script_hits "$f" "RDP Security Layer|Native RDP|CredSSP .*: SUPPORTED" | dedupe_hosts >> "$dir/affected-weaksec.txt"
        while read -r ip; do
          [[ -n "$ip" ]] && add_finding "$ip" "$port" "rdp" "RDP legacy security layer offered (NLA not enforced)" \
            "" "" "" "rdp/rdp-$port.nmap"
        done < <(nmap_script_hits "$f" "RDP Security Layer|Native RDP|CredSSP .*: SUPPORTED" | dedupe_hosts)
      fi
      if [[ "$RDP_BLUEKEEP" == "1" ]]; then
        cmd="use auxiliary/scanner/rdp/cve_2019_0708_bluekeep ; set RHOSTS file:${base} ; set RPORT ${port} ; set THREADS ${THREADS} ; spool rdp-${port}-bluekeep.txt ; run ; exit -y"
        [[ $DRYRUN -eq 0 ]] && log "rdp: msf BlueKeep check on port $port (RDP_BLUEKEEP=1)"
        msf_run "$dir" "rdp-${port}-bluekeep-console.log" "$cmd"
        if [[ $DRYRUN -eq 0 ]]; then
          strip_ansi < "$dir/rdp-${port}-bluekeep.txt" 2>/dev/null \
            | grep -Ei 'is vulnerable' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | dedupe_hosts >> "$dir/affected-bluekeep.txt"
          while read -r ip; do
            [[ -n "$ip" ]] && add_finding "$ip" "$port" "rdp" "BlueKeep (CVE-2019-0708) vulnerable" \
              "" "" "" "rdp/rdp-${port}-bluekeep.txt"
          done < <(dedupe_hosts < "$dir/affected-bluekeep.txt")
        fi
      fi
    done
    dedupe_file "$dir/affected-weaksec.txt"; dedupe_file "$dir/affected-bluekeep.txt"
  else
    warn "rdp: no hosts found"
  fi
  printf '%-22s : %s host(s)\n' "rdp weak-sec" "$(wc -l < "$dir/affected-weaksec.txt")" >> "$SUMMARY"
  [[ "$RDP_BLUEKEEP" == "1" ]] && \
    printf '%-22s : %s host(s)\n' "rdp bluekeep" "$(wc -l < "$dir/affected-bluekeep.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# IPMI (UDP 623) - cipher-zero auth bypass + RAKP 2.0 hash disclosure
# --------------------------------------------------------------------------- #
if want ipmi; then
  dir="$OUTDIR/ipmi"; mkdir -p "$dir"
  : > "$dir/affected-cipher0.txt"; : > "$dir/affected-hashes.txt"
  awk -F'\t' '$2=="623" {print $1}' "$UDP_TSV" | dedupe_hosts > "$dir/ipmi-623.txt"
  check_hostnames "$dir/ipmi-623.txt" "ipmi/ipmi-623.txt"
  if [[ -s "$dir/ipmi-623.txt" ]]; then
    ok "ipmi: $(wc -l < "$dir/ipmi-623.txt") host(s) -> ipmi/ipmi-623.txt"
    cmd="use auxiliary/scanner/ipmi/ipmi_cipher_zero ; set RHOSTS file:ipmi-623.txt ; set THREADS ${THREADS} ; spool ipmi-cipher0.txt ; run ; exit -y"
    [[ $DRYRUN -eq 0 ]] && log "ipmi: msf ipmi_cipher_zero"
    msf_run "$dir" "ipmi-cipher0-console.log" "$cmd"
    cmd="use auxiliary/scanner/ipmi/ipmi_dumphashes ; set RHOSTS file:ipmi-623.txt ; set OUTPUT_HASHCAT_FILE ipmi-hashes.hashcat ; set THREADS ${THREADS} ; spool ipmi-dumphashes.txt ; run ; exit -y"
    [[ $DRYRUN -eq 0 ]] && log "ipmi: msf ipmi_dumphashes (RAKP)"
    msf_run "$dir" "ipmi-dumphashes-console.log" "$cmd"
    if [[ $DRYRUN -eq 0 ]]; then
      strip_ansi < "$dir/ipmi-cipher0.txt" 2>/dev/null \
        | grep -Ei 'vulnerable' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | dedupe_hosts >> "$dir/affected-cipher0.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "623" "ipmi" "IPMI cipher-zero authentication bypass" "" "" "" "ipmi/ipmi-cipher0.txt"
      done < <(dedupe_hosts < "$dir/affected-cipher0.txt")
      strip_ansi < "$dir/ipmi-dumphashes.txt" 2>/dev/null \
        | grep -Ei 'hash' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | dedupe_hosts >> "$dir/affected-hashes.txt"
      while read -r ip; do
        [[ -n "$ip" ]] && add_finding "$ip" "623" "ipmi" "IPMI 2.0 RAKP password hash disclosure" "" "" "" "ipmi/ipmi-hashes.hashcat"
      done < <(dedupe_hosts < "$dir/affected-hashes.txt")
    fi
  else
    warn "ipmi: no hosts found (needs a UDP scan of port 623)"
  fi
  printf '%-22s : %s host(s)\n' "ipmi cipher-zero" "$(wc -l < "$dir/affected-cipher0.txt")" >> "$SUMMARY"
  printf '%-22s : %s host(s)\n' "ipmi rakp-hashes" "$(wc -l < "$dir/affected-hashes.txt")"  >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# Simple single-finding NSE checks (LDAP / MongoDB / rsync / X11 / finger)
# --------------------------------------------------------------------------- #
want ldap    && simple_nse_check ldap "$LDAP_PORT" "$LDAP_RE" ldap-rootdse \
  "namingContexts|rootDomainNamingContext|supportedLDAPVersion" \
  "LDAP rootDSE readable anonymously" "ldap rootdse"

want mongodb && simple_nse_check mongodb "$MONGODB_PORT" "$MONGODB_RE" "mongodb-info,mongodb-databases" \
  "totalSize|buildInfo|Build info|ok = " \
  "MongoDB unauthenticated access" "mongodb unauth" heur

want rsync   && simple_nse_check rsync "$RSYNC_PORT" "$RSYNC_RE" rsync-list-modules \
  "rsync-list-modules" \
  "rsync anonymous module listing" "rsync anon" heur

want x11     && simple_nse_check x11 "$X11_PORT" "$X11_RE" x11-access \
  "access is granted|X server access is granted" \
  "X11 open access (no authentication)" "x11 open"

want finger  && simple_nse_check finger "$FINGER_PORT" "$FINGER_RE" finger \
  "finger" \
  "finger service exposes user information" "finger" heur

# --------------------------------------------------------------------------- #
# DNS zone transfer (AXFR) - needs the zone name(s) via DNS_ZONES
# --------------------------------------------------------------------------- #
if want dns; then
  dir="$OUTDIR/dns"; mkdir -p "$dir"; : > "$dir/affected.txt"
  if [[ -z "$DNS_ZONES" ]]; then
    warn "dns: set DNS_ZONES='zone1,zone2' to test AXFR (needs the zone, not just an IP) - skipping"
  elif build_hostlists "dns" "$DNS_PORT" "$DNS_RE" "$dir"; then
    IFS=',' read -r -a _zones <<<"$DNS_ZONES"
    for hf in "$dir"/dns-*.txt; do
      base="$(basename "$hf")"
      [[ "$base" =~ ^dns-([0-9]+)\.txt$ ]] || continue
      port="${BASH_REMATCH[1]}"
      for z in "${_zones[@]}"; do
        [[ -n "$z" ]] || continue
        nmap_run "$dir" -Pn "${NMAP_TO[@]}" $NMAP_EXTRA -p "$port" \
                 --script dns-zone-transfer --script-args "dns-zone-transfer.domain=$z" \
                 -iL "$base" -oA "dns-axfr-${z}-$port"
        [[ $DRYRUN -eq 0 ]] || continue
        nmap_script_hits "$dir/dns-axfr-${z}-$port.nmap" "dns-zone-transfer" | dedupe_hosts >> "$dir/affected.txt"
        while read -r ip; do
          [[ -n "$ip" ]] && add_finding "$ip" "$port" "dns" "DNS zone transfer (AXFR) allowed for $z" \
            "" "$z" "" "dns/dns-axfr-${z}-$port.nmap"
        done < <(nmap_script_hits "$dir/dns-axfr-${z}-$port.nmap" "dns-zone-transfer" | dedupe_hosts)
      done
    done
    dedupe_file "$dir/affected.txt"
  else
    warn "dns: no hosts found"
  fi
  printf '%-22s : %s host(s)  [HEURISTIC]\n' "dns zone-transfer" "$(wc -l < "$dir/affected.txt")" >> "$SUMMARY"
fi

# --------------------------------------------------------------------------- #
# Legacy r-services (exec/login/shell on 512/513/514) - presence is the finding
# --------------------------------------------------------------------------- #
if want rservices; then
  dir="$OUTDIR/rservices"; mkdir -p "$dir"; : > "$dir/affected.txt"
  awk -F'\t' -v re="$RSERVICES_RE" '$4 ~ /^open/ && $5 ~ re {print $1"\t"$2"\t"$5}' "$TCP_SVC_TSV" | sort -u > "$dir/.rsvc"
  if [[ -s "$dir/.rsvc" ]]; then
    while IFS=$'\t' read -r ip port name; do
      [[ -n "$ip" ]] || continue
      echo "$ip" >> "$dir/affected.txt"
      [[ $DRYRUN -eq 0 ]] && add_finding "$ip" "$port" "rservices" "insecure legacy r-service exposed ($name)" \
        "" "" "" "service scan"
    done < "$dir/.rsvc"
    dedupe_file "$dir/affected.txt"
  else
    warn "rservices: none found (needs a -T service scan)"
  fi
  rm -f "$dir/.rsvc"
  printf '%-22s : %s host(s)\n' "rservices" "$(wc -l < "$dir/affected.txt")" >> "$SUMMARY"
fi


# --------------------------------------------------------------------------- #
# PHASE 2: TCP credential sprays - cheap protocols
#   One TCP connect + one auth exchange per guess. Fast per attempt.
# --------------------------------------------------------------------------- #
phase "PHASE 2: ftp / mysql / mssql / postgres sprays"
[[ $MSF_BATCH -eq 1 ]] && { BATCH_RC="$WORK/phase2.rc"; : > "$BATCH_RC"; BATCH_ITEMS=(); }
run_tcp_creds "${PHASE_FAST_TCP[@]}"
msf_batch_flush


# --------------------------------------------------------------------------- #
# PHASE 3: TCP credential sprays - SLOWEST, deliberately last
#   telnet: banner + prompt round-trips per guess, dead-but-listening
#           hosts burn the full TIMEOUT every attempt.
#   ssh:    full KEX per guess; servers throttle and drop connections.
#   If you have to Ctrl-C the run, everything above is already on disk.
# --------------------------------------------------------------------------- #
phase "PHASE 3: telnet / ssh sprays (slowest)"
[[ $MSF_BATCH -eq 1 ]] && { BATCH_RC="$WORK/phase3.rc"; : > "$BATCH_RC"; BATCH_ITEMS=(); }
run_tcp_creds "${PHASE_SLOW_TCP[@]}"
msf_batch_flush

# --------------------------------------------------------------------------- #
# Wrap up
# --------------------------------------------------------------------------- #
_rlog "END   findings=$(( $(wc -l < "$FINDINGS") - 1 ))"
echo
ok "Done. Output: $OUTDIR"
echo "--- summary ---"
cat "$SUMMARY"
echo
echo "findings.csv : $(( $(wc -l < "$FINDINGS") - 1 )) row(s)"
echo "run.log      : $(wc -l < "$RUNLOG") line(s)"
echo
echo "Affected-host files:"
find "$OUTDIR" -name 'affected*.txt' -printf '  %p (%s bytes)\n' 2>/dev/null | sort
