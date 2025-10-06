# BloodHoundCE — Next Steps (concise & ordered)
Working dir: ~/cptc/AD/BloodHoundCE
Files: docker-compose.yml, rusthound-ce (installed to /usr/local/bin), BloodHound.py (cloned)

---

1) move compose into working dir (if needed)
   mv ~/Downloads/docker-compose.yml ~/cptc/AD/BloodHoundCE/docker-compose.yml
   cd ~/cptc/AD/BloodHoundCE

2) start stack
   docker compose up -d
   docker compose ps

3) check logs for initial admin password
   # watch logs live
   docker compose logs -f --tail 200
   # quick search
   docker compose logs --no-color --tail 500 bloodhound | grep -i -E "initial|password|admin" -n || true

4) if port(s) are in use (common: 7474, 7687, 8080)
   # list processes using those ports
   sudo ss -lntp | grep -E ':(7474|7687|8080|7475|7688)'
   # or for a single port, e.g. 7474
   sudo lsof -nP -iTCP:7474 -sTCP:LISTEN

   # inspect process and command
   sudo ps -fp <PID>
   tr '\0' ' ' </proc/<PID>/cmdline ; echo

   # kill if safe
   sudo kill <PID>
   sleep 2
   sudo kill -9 <PID>   # only if needed

   # docker container mapping port?
   docker ps --filter "publish=7474" --filter "publish=7687"
   docker stop <container_id> && docker rm <container_id>

   # or change docker-compose port binding (example)
   # in docker-compose.yml:
   #   ports:
   #     - "127.0.0.1:7475:7474"
   #     - "127.0.0.1:7688:7687"
   # then:
   docker compose down
   docker compose up -d

5) missed the initial password / want to recreate (destroys DB data)
   docker compose down -v
   docker compose up -d
   docker compose logs -f --tail 200 bloodhound

6) reset Neo4j password inside container (if Neo4j is containerized)
   docker compose ps
   docker exec -it <neo4j_container_name> /bin/bash -l
   # inside:
   bin/neo4j-admin set-initial-password 'MyNewSecurePassw0rd!'
   exit
   docker compose restart

7) collect AD data (RustHound-CE)
   # run from a machine that can reach AD (replace values)
   rusthound-ce -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -z
   # produces rusthound_ce_YYYYMMDD_HHMMSS.zip (ready to upload)

8) collect AD data (BloodHound.py / bloodhound-ce-python)
   # install on collector if needed:
   pipx install git+https://github.com/dirkjanm/BloodHound.py@bloodhound-ce
   # run:
   bloodhound-ce-python -d <DOMAIN> -u <USER> -p '<PASSWORD>' --zip

9) upload to BloodHound CE
   # UI:
   http://<kali_ip_or_localhost>:8080/ui/login
   # Settings → Administration → Data Collection → File Ingest → UPLOAD FILES

   # API (after creating API token in UI)
   curl -H "Authorization: Bearer <TOKEN>" \
        -F "file=@./rusthound_ce_YYYYMMDD_HHMMSS.zip" \
        http://<host>:8080/api/v2/file-upload/

10) remote access options (choose one)
   A) Recommended — SSH local port forwarding (secure)
      From Windows (PowerShell / MobaXterm local shell):
      ssh -L 8080:localhost:8080 user@<kali_ip>
      # then open on Windows: http://localhost:8080

      # If BloodHound uses a different host port, adjust accordingly:
      ssh -L 8080:localhost:7475 user@<kali_ip>  # local:8080 -> kali:7475

   B) Bind to LAN (less secure; requires firewall control)
      # in docker-compose.yml use:
      - "8080:8080"
      # open firewall if needed:
      sudo ufw allow 8080/tcp
      # then open in browser: http://<kali_ip>:8080

11) quick troubleshooting
   docker compose logs --no-color --tail 300
   sudo ss -lntp
   Test-NetConnection -ComputerName <kali_ip> -Port 8080   # from Windows PowerShell

12) security reminders
   - Prefer SSH tunneling for access.
   - Do not expose Neo4j Bolt (7687) or Neo4j HTTP (7474) to untrusted networks.
   - Use strong admin passwords and rotate API tokens after use.
