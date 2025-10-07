#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# BloodHound CE lightweight setup (same logic, slightly refined)
# ─────────────────────────────────────────────────────────────

# Config
WORK_DIR="$HOME/BloodHoundCE"
DOCKER_KEYRING="/etc/apt/keyrings/docker.asc"
DOCKER_LIST="/etc/apt/sources.list.d/docker.list"
COMPOSE_URL="https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml"

echo "[*] Updating APT and installing gnome-terminal (required by Docker Desktop terminal integration)"
sudo apt update -y
sudo apt install -y gnome-terminal

echo "[*] Removing potentially conflicting packages (ignore errors if not installed)"
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
  sudo apt-get remove -y "$pkg" || true
done

echo "[*] Creating and entering work directory: $WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[*] Installing prerequisites for Docker repo"
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl

echo "[*] Setting up Docker APT repository (Debian bookworm)"
sudo install -m 0755 -d "$(dirname "$DOCKER_KEYRING")"
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o "$DOCKER_KEYRING"
sudo chmod a+r "$DOCKER_KEYRING"

echo "deb [arch=$(dpkg --print-architecture) signed-by=$DOCKER_KEYRING] https://download.docker.com/linux/debian bookworm stable" \
  | sudo tee "$DOCKER_LIST" >/dev/null

sudo apt-get update -y

echo "[*] Installing Docker Engine + Buildx + Compose plugin"
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[*] Starting Docker service"
sudo systemctl start docker

echo "[*] Verifying Docker with hello-world"
sudo docker run --rm hello-world

echo "[*] Fetching BloodHound CE docker-compose file"
wget -q "$COMPOSE_URL" -O docker-compose.yml
echo "    -> Saved: $WORK_DIR/docker-compose.yml"

echo "[*] Cloning BloodHound.py"
if [ ! -d "$WORK_DIR/BloodHound.py" ]; then
  git clone https://github.com/dirkjanm/BloodHound.py.git
else
  echo "    -> BloodHound.py already exists, skipping clone"
fi

echo "[*] Cloning and building RustHound-CE"
if [ ! -d "$WORK_DIR/RustHound-CE" ]; then
  git clone https://github.com/g0h4n/RustHound-CE.git
fi
cd RustHound-CE

# Install Rust (non-interactive) if missing
if ! command -v cargo >/dev/null 2>&1; then
  echo "[*] Installing Rust toolchain (rustup) non-interactively"
  curl -fsSL https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
else
  # shellcheck source=/dev/null
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi

echo "[*] Building RustHound-CE (release)"
make release

# Try the canonical target path first; fall back to project root if needed
if [ -f "target/release/rusthound-ce" ]; then
  sudo cp "target/release/rusthound-ce" /usr/bin/rusthound-ce
elif [ -f "rusthound-ce" ]; then
  sudo cp "rusthound-ce" /usr/bin/rusthound-ce
else
  echo "[!] Could not find built rusthound-ce binary" >&2
  exit 1
fi

echo "[✓] Setup complete."
echo "Next: cd \"$WORK_DIR\" && docker compose up -d  (then ingest data with rusthound-ce or bloodhound-ce python)"
