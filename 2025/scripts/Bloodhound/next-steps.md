# BloodHound CE — Setup & Usage Guide

**Working Directory:** `~/cptc/AD/BloodHoundCE`

**Required Files:**
- `docker-compose.yml`
- `rusthound-ce` (installed to `/usr/local/bin`)
- `BloodHound.py` (cloned repository)

---

## 1. Initial Setup

### Move Compose File to Working Directory

```bash
mv ~/Downloads/docker-compose.yml ~/cptc/AD/BloodHoundCE/docker-compose.yml
cd ~/cptc/AD/BloodHoundCE
```

## 2. Start the Docker Stack

```bash
docker compose up -d
docker compose ps
```

## 3. Retrieve Initial Admin Password

Watch logs live:
```bash
docker compose logs -f --tail 200
```

Quick search for password:
```bash
docker compose logs --no-color --tail 500 bloodhound | grep -i -E "initial|password|admin" -n || true
```

## 4. Troubleshoot Port Conflicts

If ports are in use (common: 7474, 7687, 8080):

### List processes using those ports:
```bash
sudo ss -lntp | grep -E ':(7474|7687|8080|7475|7688)'

# Or for a single port, e.g., 7474:
sudo lsof -nP -iTCP:7474 -sTCP:LISTEN
```

### Inspect process and command:
```bash
sudo ps -fp <PID>
tr '\0' ' ' </proc/<PID>/cmdline ; echo
```

### Kill process if safe:
```bash
sudo kill <PID>
sleep 2
sudo kill -9 <PID>   # only if needed
```

### Check if Docker container is mapping the port:
```bash
docker ps --filter "publish=7474" --filter "publish=7687"
docker stop <container_id> && docker rm <container_id>
```

### Alternative: Change Docker Compose Port Binding

Edit `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:7475:7474"
  - "127.0.0.1:7688:7687"
```

Then restart:
```bash
docker compose down
docker compose up -d
```

## 5. Reset Admin Password (Destroys DB Data)

If you missed the initial password or want to recreate:

```bash
docker compose down -v
docker compose up -d
docker compose logs -f --tail 200 bloodhound
```

## 6. Reset Neo4j Password Inside Container

If Neo4j is containerized:

```bash
docker compose ps
docker exec -it <neo4j_container_name> /bin/bash -l

# Inside the container:
bin/neo4j-admin set-initial-password 'MyNewSecurePassw0rd!'
exit

# Restart services:
docker compose restart
```

## 7. Collect AD Data (RustHound-CE)

Run from a machine that can reach Active Directory:

```bash
rusthound-ce -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -z
```

This produces `rusthound_ce_YYYYMMDD_HHMMSS.zip` ready to upload.

## 8. Collect AD Data (BloodHound.py)

### Install on collector if needed:
```bash
pipx install git+https://github.com/dirkjanm/BloodHound.py@bloodhound-ce
```

### Run collection:
```bash
bloodhound-ce-python -d <DOMAIN> -u <USER> -p '<PASSWORD>' --zip
```

## 9. Upload Data to BloodHound CE

### Via Web UI:
1. Navigate to: `http://<kali_ip_or_localhost>:8080/ui/login`
2. Go to: **Settings → Administration → Data Collection → File Ingest → UPLOAD FILES**

### Via API:
After creating an API token in the UI:

```bash
curl -H "Authorization: Bearer <TOKEN>" \
     -F "file=@./rusthound_ce_YYYYMMDD_HHMMSS.zip" \
     http://<host>:8080/api/v2/file-upload/
```

## 10. Remote Access Options

### Option A: SSH Local Port Forwarding (Recommended — Secure)

From Windows (PowerShell / MobaXterm):
```bash
ssh -L 8080:localhost:8080 user@<kali_ip>
```

Then open in browser: `http://localhost:8080`

If BloodHound uses a different host port:
```bash
ssh -L 8080:localhost:7475 user@<kali_ip>  # local:8080 -> kali:7475
```

### Option B: Bind to LAN (Less Secure)

Edit `docker-compose.yml`:
```yaml
ports:
  - "8080:8080"
```

Open firewall if needed:
```bash
sudo ufw allow 8080/tcp
```

Then open in browser: `http://<kali_ip>:8080`

## 11. Quick Troubleshooting

```bash
# Check logs:
docker compose logs --no-color --tail 300

# List listening ports:
sudo ss -lntp

# Test connection from Windows PowerShell:
Test-NetConnection -ComputerName <kali_ip> -Port 8080
```

## 12. Security Reminders

- ✅ Prefer SSH tunneling for access
- ⚠️ Do not expose Neo4j Bolt (7687) or Neo4j HTTP (7474) to untrusted networks
- 🔐 Use strong admin passwords and rotate API tokens after use
