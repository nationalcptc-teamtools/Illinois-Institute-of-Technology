#!/usr/bin/env bash
set -euo pipefail

# Minimal BloodHound CE setup for Kali (works across Kali releases)

# Config
WORK_DIR="${HOME}/BloodHoundCE"
COMPOSE_URL="https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml"
RUSTHOUND_REPO="https://github.com/g0h4n/RustHound-CE.git"

# Helpers
log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
die()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

# Detect OS
ID="$(. /etc/os-release; echo "${ID}")"

# On Kali, ensure no invalid Docker upstream entries are present
if [ "${ID}" = "kali" ]; then
  for f in /etc/apt/sources.list.d/*docker*.list; do
    [ -f "$f" ] && mv "$f" "$f.disabled" || true
  done
fi

log "Installing Docker and dependencies"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  docker.io docker-compose-plugin containerd ca-certificates curl git make gcc pkg-config

log "Ensuring Docker is running"
systemctl enable --now docker >/dev/null 2>&1 || service docker start || true

log "Preparing working directory: ${WORK_DIR}"
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

log "Downloading BloodHound CE docker-compose.yml"
curl -fsSL "${COMPOSE_URL}" -o docker-compose.yml || die "Failed to download docker-compose.yml"

log "Starting BloodHound CE stack"
docker compose up -d

log "Done. Access the UI on http://<host>:8080/ui/login"
echo "Tips:"
echo "  docker compose logs -f --tail 200   # view logs"
echo "  docker compose down                 # stop"

# Install RustHound-CE (collector)
log "Installing RustHound-CE collector"
if ! command -v cargo >/dev/null 2>&1; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y
fi
[ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"

if [ ! -d "${WORK_DIR}/RustHound-CE/.git" ]; then
  git clone "${RUSTHOUND_REPO}" "${WORK_DIR}/RustHound-CE"
fi
cd "${WORK_DIR}/RustHound-CE"
make release
BIN_SRC="target/release/rusthound-ce"
[ -f "${BIN_SRC}" ] || BIN_SRC="rusthound-ce"
install -m 0755 "${BIN_SRC}" /usr/local/bin/rusthound-ce
log "Installed RustHound-CE to /usr/local/bin/rusthound-ce"
