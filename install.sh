#!/usr/bin/env bash
# ============================================================
#  NetAdmin Portal — Installer
#  Supports: Debian, Ubuntu, Linux Mint (and derivatives)
# ============================================================

set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

INSTALL_DIR="$HOME/.local/share/netadmin"
SERVICE_NAME="netadmin"
PORT=7070

banner() {
  echo -e "\n${CYN}${BLD}"
  echo "  ███╗   ██╗███████╗████████╗ █████╗ ██████╗ ███╗   ███╗██╗███╗   ██╗"
  echo "  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║"
  echo "  ██╔██╗ ██║█████╗     ██║   ███████║██║  ██║██╔████╔██║██║██╔██╗ ██║"
  echo "  ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║  ██║██║╚██╔╝██║██║██║╚██╗██║"
  echo "  ██║ ╚████║███████╗   ██║   ██║  ██║██████╔╝██║ ╚═╝ ██║██║██║ ╚████║"
  echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝"
  echo -e "${RST}${CYN}                    N E T W O R K   A D M I N   P O R T A L${RST}"
  echo ""
}

info()    { echo -e "  ${CYN}[INFO]${RST}  $*"; }
ok()      { echo -e "  ${GRN}[ OK ]${RST}  $*"; }
warn()    { echo -e "  ${YEL}[WARN]${RST}  $*"; }
err()     { echo -e "  ${RED}[ERR ]${RST}  $*"; }
section() { echo -e "\n${BLD}${YEL}▸ $*${RST}"; }
die()     { err "$*"; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
banner

section "PREFLIGHT CHECKS"

# OS check
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
  info "Detected OS: ${PRETTY_NAME:-$DISTRO}"
else
  warn "Cannot detect OS — assuming Debian-compatible."
  DISTRO="debian"; DISTRO_LIKE="debian"
fi

IS_DEBIAN=0
for d in $DISTRO $DISTRO_LIKE; do
  case "$d" in debian|ubuntu|linuxmint|mint|pop|elementary|zorin|kali|raspbian) IS_DEBIAN=1 ;; esac
done
[[ $IS_DEBIAN -eq 1 ]] || warn "OS not Debian-based. apt commands may fail — proceed with caution."

# Root check
if [[ $EUID -eq 0 ]]; then
  SUDO=""
  warn "Running as root."
else
  if command -v sudo &>/dev/null; then
    SUDO="sudo"
    ok "sudo available."
  else
    die "sudo not found and not running as root. Install sudo or run as root."
  fi
fi

# Internet check
section "CONNECTIVITY CHECK"
if curl -sf --max-time 5 https://pypi.org > /dev/null 2>&1; then
  ok "Internet accessible (pypi.org reachable)."
else
  warn "Cannot reach pypi.org. Package download may fail."
fi

if $SUDO apt-get update -qq --dry-run > /dev/null 2>&1; then
  ok "apt repositories accessible."
else
  warn "apt dry-run failed — may need 'apt-get update' manually."
fi

# ── Dependency Resolution ─────────────────────────────────────────────────────
section "DEPENDENCY RESOLUTION"

APT_NEEDED=()
PIP_NEEDED=()

check_cmd() {
  local cmd="$1" pkg="$2"
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd already installed."
  else
    warn "$cmd not found — will install ($pkg)."
    APT_NEEDED+=("$pkg")
  fi
}

check_python_pkg() {
  local pkg="$1"
  if python3 -c "import $pkg" 2>/dev/null; then
    ok "python3 module '$pkg' already available."
  else
    warn "python3 module '$pkg' not found — will install."
    PIP_NEEDED+=("$pkg")
  fi
}

check_cmd python3     python3
check_cmd pip3        python3-pip
check_cmd nmap        nmap
check_cmd arp-scan    arp-scan
check_cmd traceroute  traceroute
check_cmd ip          iproute2
check_cmd ping        iputils-ping

check_python_pkg flask

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ ${#APT_NEEDED[@]} -gt 0 ]]; then
  info "apt packages to install: ${APT_NEEDED[*]}"
else
  info "All system dependencies satisfied."
fi
if [[ ${#PIP_NEEDED[@]} -gt 0 ]]; then
  info "pip packages to install: ${PIP_NEEDED[*]}"
else
  info "All Python dependencies satisfied."
fi

echo ""
read -rp "  Proceed with installation? [Y/n] " CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

# ── Install System Packages ───────────────────────────────────────────────────
if [[ ${#APT_NEEDED[@]} -gt 0 ]]; then
  section "INSTALLING SYSTEM PACKAGES"
  info "Running apt-get update..."
  $SUDO apt-get update -qq

  for pkg in "${APT_NEEDED[@]}"; do
    info "Installing $pkg..."
    if $SUDO apt-get install -y -qq "$pkg" 2>&1 | tail -1; then
      ok "$pkg installed."
    else
      err "Failed to install $pkg. You may need to install it manually."
    fi
  done
fi

# ── Install Python Packages ───────────────────────────────────────────────────
if [[ ${#PIP_NEEDED[@]} -gt 0 ]]; then
  section "INSTALLING PYTHON PACKAGES"
  # Prefer venv on modern Debian/Ubuntu which blocks global pip installs
  VENV_DIR="$INSTALL_DIR/venv"
  if python3 -m venv --help &>/dev/null; then
    info "Creating Python virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    PYTHON="$VENV_DIR/bin/python3"
    PIP="$VENV_DIR/bin/pip"
    ok "Virtual environment created."
  else
    PYTHON="python3"
    PIP="pip3"
    warn "python3-venv not available — installing globally (may require --break-system-packages)."
  fi

  "$PIP" install --quiet "${PIP_NEEDED[@]}" || \
    "$PIP" install --quiet --break-system-packages "${PIP_NEEDED[@]}" || \
    die "pip install failed. Try manually: pip3 install ${PIP_NEEDED[*]}"
  ok "Python packages installed."
else
  PYTHON="${INSTALL_DIR}/venv/bin/python3"
  [[ -x "$PYTHON" ]] || PYTHON="python3"
fi

# ── Install Application Files ─────────────────────────────────────────────────
section "INSTALLING NETADMIN FILES"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Source directory: $SCRIPT_DIR"
info "Install directory: $INSTALL_DIR"

mkdir -p "$INSTALL_DIR/static"

# Copy server and frontend
if [[ -f "$SCRIPT_DIR/server.py" ]]; then
  cp -f "$SCRIPT_DIR/server.py"       "$INSTALL_DIR/server.py"
  cp -f "$SCRIPT_DIR/static/index.html" "$INSTALL_DIR/static/index.html"
  ok "Application files copied."
else
  die "server.py not found in $SCRIPT_DIR — make sure install.sh is in the same folder as server.py"
fi

# ── Create Launcher Script ────────────────────────────────────────────────────
section "CREATING LAUNCHER"

LAUNCHER="$HOME/.local/bin/netadmin"
mkdir -p "$HOME/.local/bin"

# Detect python to use
if [[ -x "$INSTALL_DIR/venv/bin/python3" ]]; then
  PY_EXEC="$INSTALL_DIR/venv/bin/python3"
else
  PY_EXEC="$(command -v python3)"
fi

cat > "$LAUNCHER" << LAUNCH
#!/usr/bin/env bash
# NetAdmin Portal launcher
cd "$INSTALL_DIR"
exec "$PY_EXEC" server.py "\$@"
LAUNCH
chmod +x "$LAUNCHER"
ok "Launcher created at $LAUNCHER"

# Add to PATH if needed
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  warn "$HOME/.local/bin not in PATH."
  info "Add this to your ~/.bashrc or ~/.zshrc:"
  echo -e "     ${CYN}export PATH=\"\$HOME/.local/bin:\$PATH\"${RST}"
fi

# ── Systemd Service (Optional) ───────────────────────────────────────────────
section "SYSTEMD SERVICE (OPTIONAL)"
echo ""
read -rp "  Install as a systemd user service (auto-start on login)? [y/N] " SYSDSVC
SYSDSVC="${SYSDSVC:-N}"

if [[ "$SYSDSVC" =~ ^[Yy]$ ]]; then
  SVCDIR="$HOME/.config/systemd/user"
  mkdir -p "$SVCDIR"
  cat > "$SVCDIR/${SERVICE_NAME}.service" << SVC
[Unit]
Description=NetAdmin Portal — Network Administration Dashboard
After=network.target

[Service]
Type=simple
ExecStart=$PY_EXEC $INSTALL_DIR/server.py
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
SVC

  systemctl --user daemon-reload
  systemctl --user enable "${SERVICE_NAME}.service"
  systemctl --user start  "${SERVICE_NAME}.service"
  ok "Systemd user service '${SERVICE_NAME}' enabled and started."
  info "Control with:  systemctl --user {start|stop|restart|status} ${SERVICE_NAME}"
else
  info "Skipping systemd setup — run manually with: netadmin"
fi

# ── Sudo for nmap/arp-scan ────────────────────────────────────────────────────
section "PRIVILEGE SETUP"
info "nmap OS detection and arp-scan work best with elevated privileges."
echo ""
read -rp "  Add sudoers rule for nmap and arp-scan (no password)? [y/N] " SUDOYES
SUDOYES="${SUDOYES:-N}"

if [[ "$SUDOYES" =~ ^[Yy]$ ]]; then
  NMAP_PATH="$(command -v nmap || echo /usr/bin/nmap)"
  ARPSCAN_PATH="$(command -v arp-scan || echo /usr/sbin/arp-scan)"
  SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: $NMAP_PATH, $ARPSCAN_PATH"
  SUDOERS_FILE="/etc/sudoers.d/netadmin"
  echo "$SUDOERS_LINE" | $SUDO tee "$SUDOERS_FILE" > /dev/null
  $SUDO chmod 440 "$SUDOERS_FILE"
  ok "Sudoers rule added: $SUDOERS_FILE"
else
  warn "Skipped. OS detection may be limited. You can run the portal with sudo for full features."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════════════════╗"
echo    "║          NETADMIN PORTAL — INSTALLATION COMPLETE         ║"
echo -e "╚══════════════════════════════════════════════════════════╝${RST}"
echo ""
ok "Run the portal:  ${BLD}netadmin${RST}  (or: ${BLD}$LAUNCHER${RST})"
ok "Open browser:    ${BLD}http://localhost:${PORT}${RST}"
ok "Network access:  ${BLD}http://$(hostname -I | awk '{print $1}'):${PORT}${RST}"
echo ""
info "The portal will auto-scan your network on startup."
info "No browser extensions or other apps required."
echo ""

# Offer to launch now
read -rp "  Launch NetAdmin Portal now? [Y/n] " LAUNCH_NOW
LAUNCH_NOW="${LAUNCH_NOW:-Y}"
if [[ "$LAUNCH_NOW" =~ ^[Yy]$ ]]; then
  echo ""
  info "Starting portal... open http://localhost:${PORT} in your browser."
  info "Press Ctrl+C to stop."
  echo ""
  exec "$LAUNCHER"
fi
