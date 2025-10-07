#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# - Installs Docker (official repo on Debian/Ubuntu; distro pkg on Kali)
# - Downloads compose file, clones BloodHound.py, builds RustHound-CE
# ─────────────────────────────────────────────────────────────

# ---------- Config ----------
WORK_DIR="${HOME}/BloodHoundCE"
DOCKER_KEYRING="/etc/apt/keyrings/docker.asc"
DOCKER_LIST="/etc/apt/sources.list.d/docker.list"
COMPOSE_URL="https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml"

# ---------- Helpers ----------
log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
die()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# ---------- Detect OS ----------
ID="$(. /etc/os-release; echo "${ID}")"
CODENAME="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
log "Detected OS: ID=${ID}, CODENAME=${CODENAME:-unknown}"

# ---------- Kali apt source hygiene (avoid invalid Docker upstream on Kali) ----------
if [ "${ID}" = "kali" ]; then
  # Disable any docker.com apt lists that point to non-existent kali suites
  if grep -Rqs "download.docker.com" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    warn "Disabling Docker upstream apt entries on Kali (not supported)"
    for f in /etc/apt/sources.list.d/*docker*.list; do
      [ -f "$f" ] && mv "$f" "$f.disabled" || true
    done
    # Also remove the path we might write later to avoid confusion
    rm -f "${DOCKER_LIST}" 2>/dev/null || true
    # Keyring removal is harmless if absent
    rm -f "${DOCKER_KEYRING}" 2>/dev/null || true
  fi
fi

# ---------- Base packages ----------
log "Updating APT and installing base tools"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release git make gcc pkg-config

# Install gnome-terminal if not present
if ! dpkg -s gnome-terminal >/dev/null 2>&1; then
  apt-get install -y gnome-terminal || true
fi

# ---------- Remove conflicting Docker packages ----------
log "Removing potentially conflicting Docker packages"
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
  apt-get remove -y "$pkg" >/dev/null 2>&1 || true
done

# ---------- Create work dir ----------
log "Creating working directory: ${WORK_DIR}"
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

# ---------- Docker install (universal) ----------
install_docker_deb_repo() {
  # Official Docker repo for Debian/Ubuntu
  install -m 0755 -d "$(dirname "${DOCKER_KEYRING}")"
  curl -fsSL https://download.docker.com/linux/debian/gpg -o "${DOCKER_KEYRING}"
  chmod a+r "${DOCKER_KEYRING}"

  # Detect codename if missing (Ubuntu sometimes)
  if [ -z "${CODENAME}" ]; then
    CODENAME="$(lsb_release -cs || true)"
  fi
  [ -z "${CODENAME}" ] && die "Could not determine distribution codename."

  echo "deb [arch=$(dpkg --print-architecture) signed-by=${DOCKER_KEYRING}] \
https://download.docker.com/linux/debian ${CODENAME} stable" \
  > "${DOCKER_LIST}"

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_kali() {
  # Docker Inc. does not publish a Kali suite; use distro packages
  # (docker.io + docker-compose-plugin exist on Kali rolling)
  apt-get update -y
  apt-get install -y docker.io docker-compose-plugin containerd
}

log "Installing Docker for ${ID}"
case "${ID}" in
  debian|ubuntu)
    if ! (install_docker_deb_repo); then
      warn "Official Docker repo failed; falling back to distro packages."
      apt-get install -y docker.io docker-compose-plugin containerd || die "Docker install failed."
    fi
    ;;
  kali)
    install_docker_kali
    ;;
  *)
    warn "Unknown distro (${ID}). Trying official Docker repo path."
    if ! (install_docker_deb_repo); then
      warn "Repo attempt failed; falling back to distro packages."
      apt-get install -y docker.io docker-compose-plugin containerd || die "Docker install failed."
    fi
    ;;
esac

# Enable & start Docker
systemctl enable --now docker >/dev/null 2>&1 || service docker start || true

# Verify Docker runs containers
log "Verifying Docker with hello-world"
docker run --rm hello-world >/dev/null || warn "Docker test failed; daemon may still be starting"

# ---------- BloodHound compose ----------
log "Fetching BloodHound CE docker-compose.yml"
curl -fsSL "${COMPOSE_URL}" -o docker-compose.yml || die "Failed to download docker-compose.yml"
log "Saved: ${WORK_DIR}/docker-compose.yml"

# ---------- BloodHound.py ----------
log "Cloning BloodHound.py"
if [ ! -d "${WORK_DIR}/BloodHound.py/.git" ]; then
  git clone https://github.com/dirkjanm/BloodHound.py.git
else
  log "BloodHound.py already present"
fi

# ---------- RustHound-CE ----------
log "Cloning RustHound-CE"
if [ ! -d "${WORK_DIR}/RustHound-CE/.git" ]; then
  git clone https://github.com/g0h4n/RustHound-CE.git
fi

log "Ensuring Rust toolchain is installed"
if ! command -v cargo >/dev/null 2>&1; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck source=/dev/null
[ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"

log "Building RustHound-CE"
cd "${WORK_DIR}/RustHound-CE"
make release
BIN_SRC="target/release/rusthound-ce"
[ -f "${BIN_SRC}" ] || BIN_SRC="rusthound-ce"
[ -f "${BIN_SRC}" ] || die "RustHound-CE build did not produce a binary."

install -m 0755 "${BIN_SRC}" /usr/local/bin/rusthound-ce
log "Installed: /usr/local/bin/rusthound-ce"

# ---------- Done ----------
log "Setup complete ✔"
echo "Next:"
echo "  cd ${WORK_DIR}"
echo "  docker compose up -d"
echo "  docker compose logs -f --tail 200   # find initial admin password"
echo "  rusthound-ce -d <DOMAIN> -u '<USER>' -p '<PASS>' -z"
