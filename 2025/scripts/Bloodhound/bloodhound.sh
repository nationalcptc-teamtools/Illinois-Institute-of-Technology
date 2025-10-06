#!/usr/bin/env bash
set -euo pipefail
# install_bloodhound_ce.sh
# Purpose: install Docker, download BloodHound CE docker-compose, build RustHound-CE, clone BloodHound.py.
# Usage: sudo ./install_bloodhound_ce.sh
# Edit variables below if desired.

# ---------- Config ----------
WORKDIR="$HOME/cptc/AD/BloodHoundCE"
RUSTHOUND_DIR="$WORKDIR/rhce"
BH_PY_DIR="$WORKDIR/BloodHound.py"
COMPOSE_URL="https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml"
COMPOSE_NAME="docker-compose.yml"

# ---------- Helpers ----------
info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

# ---------- Create working dir ----------
info "Creating working directory: $WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# ---------- Install Docker (Debian/Ubuntu/Bookworm) ----------
info "Installing Docker (apt-get)..."
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

info "Verifying Docker..."
if ! docker run --rm hello-world >/dev/null 2>&1; then
  warn "docker hello-world failed — inspect Docker installation logs."
else
  info "Docker installation looks good."
fi

# ---------- Download Docker Compose file ----------
info "Downloading BloodHound example docker-compose.yml"
curl -fsSL "$COMPOSE_URL" -o "$WORKDIR/$COMPOSE_NAME"
info "Saved: $WORKDIR/$COMPOSE_NAME"

# ---------- RustHound-CE build ----------
info "Cloning RustHound-CE and building"
if [ ! -d "$RUSTHOUND_DIR" ]; then
  mkdir -p "$RUSTHOUND_DIR"
  git clone https://github.com/g0h4n/RustHound-CE.git "$RUSTHOUND_DIR"
fi
cd "$RUSTHOUND_DIR"
# Install Rust toolchain if missing
if ! command -v cargo >/dev/null 2>&1; then
  info "Installing Rust toolchain (rustup) - noninteractive"
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
fi
info "Building RustHound-CE (release)"
make release
# copy binary (try common target paths)
if [ -f target/release/rusthound-ce ]; then
  sudo cp -f target/release/rusthound-ce /usr/local/bin/rusthound-ce
elif [ -f rusthound-ce ]; then
  sudo cp -f rusthound-ce /usr/local/bin/rusthound-ce
else
  warn "rusthound-ce binary not found after build."
fi
info "rusthound-ce installed to /usr/local/bin/rusthound-ce (if build succeeded)"

# ---------- BloodHound.py clone (CE branch recommended) ----------
info "Cloning BloodHound.py (recommended branch: bloodhound-ce)"
cd "$WORKDIR"
if [ ! -d "$BH_PY_DIR" ]; then
  git clone https://github.com/dirkjanm/BloodHound.py.git "$BH_PY_DIR"
fi

info "Setup complete. Working directory: $WORKDIR"
echo
echo "Next steps (concise):"
echo "  1) cd $WORKDIR"
echo "  2) edit docker-compose.yml if you need to change host port bindings"
echo "  3) docker compose up -d"
echo "  4) use rusthound-ce or bloodhound-ce python ingestor to collect and create zip"
