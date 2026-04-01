#!/usr/bin/env bash
# ============================================================
#  NetAdmin Portal — Installer v2
#  Supports: Debian, Ubuntu, Linux Mint (and derivatives)
#  Every dependency has multiple installation fallback methods.
#  The end-user should never need to manually install anything.
# ============================================================

set -uo pipefail   # no -e so we handle failures ourselves

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

INSTALL_DIR="$HOME/.local/share/netadmin"
SERVICE_NAME="netadmin"
PORT=7070
FAILED_DEPS=()

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
section() { echo -e "\n${BLD}${YEL}>>> $*${RST}"; }
die()     { err "$*"; exit 1; }

# ============================================================
# PREFLIGHT
# ============================================================
banner
section "PREFLIGHT CHECKS"

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
[[ $IS_DEBIAN -eq 1 ]] || warn "OS may not be Debian-based. apt commands may fail."

if [[ $EUID -eq 0 ]]; then
  SUDO=""
  warn "Running as root."
elif command -v sudo &>/dev/null; then
  SUDO="sudo"
  ok "sudo is available."
else
  die "sudo not found and not running as root. Install sudo or re-run as root."
fi

# ============================================================
# CONNECTIVITY
# ============================================================
section "CONNECTIVITY CHECK"
HAVE_INTERNET=0
for host in pypi.org archive.ubuntu.com deb.debian.org 1.1.1.1; do
  if curl -sf --max-time 5 "https://$host" >/dev/null 2>&1 \
     || wget -q  --timeout=5 "https://$host" -O /dev/null 2>/dev/null; then
    HAVE_INTERNET=1
    ok "Internet reachable (tested $host)."
    break
  fi
done
[[ $HAVE_INTERNET -eq 1 ]] || warn "Internet appears unreachable — installation may fail."

section "UPDATING APT PACKAGE INDEX"
$SUDO apt-get update -qq 2>/dev/null && ok "apt index updated." \
  || warn "apt-get update failed — will attempt install using cached index."

# ============================================================
# HELPERS
# ============================================================

# try_apt <pkg> [<pkg2> ...]  — tries each package name in order, stops on first success
try_apt() {
  for pkg in "$@"; do
    info "    apt: trying '$pkg'…"
    if $SUDO apt-get install -y -qq "$pkg" >/dev/null 2>&1; then
      ok "    Installed '$pkg' via apt."
      return 0
    fi
  done
  return 1
}

# ============================================================
# PYTHON 3
# ============================================================
section "PYTHON 3"
if command -v python3 &>/dev/null; then
  ok "python3 found: $(python3 --version 2>&1)"
else
  warn "python3 not found — installing…"
  try_apt python3 python3-minimal \
    || die "Cannot install python3. Please run:  sudo apt-get install python3"
fi
PYTHON3="$(command -v python3)"

# ============================================================
# VENV (for isolated Flask install)
# ============================================================
section "PYTHON VENV"
VENV_DIR="$INSTALL_DIR/venv"
VENV_OK=0

if python3 -m venv --help >/dev/null 2>&1; then
  ok "python3 venv module is available."
  VENV_OK=1
else
  info "venv not found — trying to install…"
  if try_apt python3-venv python3-full python3-virtualenv; then
    VENV_OK=1
  else
    warn "venv unavailable — will install Flask globally (may require --break-system-packages)."
  fi
fi

mkdir -p "$INSTALL_DIR"
if [[ $VENV_OK -eq 1 ]]; then
  if python3 -m venv "$VENV_DIR" >/dev/null 2>&1; then
    PY_EXEC="$VENV_DIR/bin/python3"
    PIP_EXEC="$VENV_DIR/bin/pip"
    ok "Virtual environment ready at $VENV_DIR"
  else
    warn "venv creation failed — using system python."
    PY_EXEC="$PYTHON3"
    PIP_EXEC=""
    VENV_OK=0
  fi
else
  PY_EXEC="$PYTHON3"
  PIP_EXEC=""
fi

# ============================================================
# FLASK  — 5-method waterfall
# ============================================================
section "FLASK (web framework)"

flask_installed() {
  "$PY_EXEC" -c "import flask" >/dev/null 2>&1
}

install_flask() {
  # -- Method 1: pip inside venv (safest) --
  if [[ -x "${VENV_DIR}/bin/pip" ]]; then
    info "  [1/5] pip install flask (venv)…"
    if "${VENV_DIR}/bin/pip" install --quiet flask 2>/dev/null; then
      ok "  Flask installed via pip (venv)."; return 0
    fi
  fi

  # -- Method 2: pip3 --
  if command -v pip3 &>/dev/null; then
    info "  [2/5] pip3 install flask…"
    if pip3 install --quiet flask 2>/dev/null; then
      ok "  Flask installed via pip3."; return 0
    fi
    info "  [2b]  pip3 install flask --break-system-packages…"
    if pip3 install --quiet --break-system-packages flask 2>/dev/null; then
      ok "  Flask installed via pip3 (--break-system-packages)."; return 0
    fi
  fi

  # -- Method 3: python3 -m pip --
  info "  [3/5] python3 -m pip install flask…"
  if python3 -m pip install --quiet flask 2>/dev/null; then
    ok "  Flask installed via python3 -m pip."; return 0
  fi
  if python3 -m pip install --quiet --break-system-packages flask 2>/dev/null; then
    ok "  Flask installed via python3 -m pip (--break-system-packages)."; return 0
  fi

  # -- Method 4: apt python3-flask --
  info "  [4/5] apt-get install python3-flask…"
  if try_apt python3-flask; then
    ok "  Flask installed via apt (python3-flask)."; return 0
  fi

  # -- Method 5: pip inside a fresh venv bootstrapped with ensurepip --
  info "  [5/5] bootstrap pip with ensurepip + install…"
  local tmp_venv="/tmp/netadmin_bootstrap_venv"
  if python3 -m ensurepip --upgrade >/dev/null 2>&1; then
    if python3 -m pip install --quiet flask 2>/dev/null \
       || python3 -m pip install --quiet --break-system-packages flask 2>/dev/null; then
      ok "  Flask installed via ensurepip bootstrap."; return 0
    fi
  fi
  # Try creating a fresh venv with --copies --without-pip then manually get pip
  if python3 -m venv --clear "$tmp_venv" >/dev/null 2>&1; then
    if "$tmp_venv/bin/python3" -m ensurepip >/dev/null 2>&1 \
       && "$tmp_venv/bin/pip" install --quiet flask >/dev/null 2>&1; then
      # Copy the venv into place
      rsync -a "$tmp_venv/" "$VENV_DIR/" 2>/dev/null \
        || cp -r "$tmp_venv/." "$VENV_DIR/"
      PY_EXEC="$VENV_DIR/bin/python3"
      ok "  Flask installed via bootstrap venv."; return 0
    fi
  fi

  return 1
}

if flask_installed; then
  ok "Flask already available."
else
  install_flask
  if flask_installed; then
    ok "Flask is ready."
  else
    err "Flask installation failed through all 5 methods."
    FAILED_DEPS+=("flask (python3-flask)")
  fi
fi

# ============================================================
# NMAP
# ============================================================
section "NMAP"
if command -v nmap &>/dev/null; then
  ok "nmap present: $(nmap --version 2>&1 | head -1)"
else
  info "Installing nmap…"
  try_apt nmap \
    || { err "nmap install failed."; FAILED_DEPS+=("nmap"); }
fi

# ============================================================
# ARP-SCAN
# ============================================================
section "ARP-SCAN"
if command -v arp-scan &>/dev/null; then
  ok "arp-scan present."
else
  info "Installing arp-scan…"
  try_apt arp-scan \
    || { err "arp-scan install failed."; FAILED_DEPS+=("arp-scan"); }
fi

# ============================================================
# TRACEROUTE
# ============================================================
section "TRACEROUTE"
if command -v traceroute &>/dev/null; then
  ok "traceroute present."
else
  info "Installing traceroute…"
  try_apt traceroute inetutils-traceroute \
    || { err "traceroute install failed."; FAILED_DEPS+=("traceroute"); }
fi

# ============================================================
# NETWORK UTILS (ip, ping)
# ============================================================
section "NETWORK UTILITIES"
declare -A TOOL_PKGS=( ["ip"]="iproute2" ["ping"]="iputils-ping" )
for tool in ip ping; do
  if command -v "$tool" &>/dev/null; then
    ok "$tool present."
  else
    pkg="${TOOL_PKGS[$tool]}"
    info "Installing $pkg for '$tool'…"
    try_apt "$pkg" || warn "$tool unavailable — some features limited."
  fi
done

# ============================================================
# FAILURE SUMMARY
# ============================================================
echo ""
if [[ ${#FAILED_DEPS[@]} -gt 0 ]]; then
  err "The following could NOT be installed automatically:"
  for dep in "${FAILED_DEPS[@]}"; do echo -e "    ${RED}  x  $dep${RST}"; done
  echo ""
  warn "NetAdmin will run with reduced functionality."
  warn "Manual install attempt:  sudo apt-get install ${FAILED_DEPS[*]}"
  echo ""
  read -rp "  Continue anyway? [y/N] " CONT
  [[ "${CONT:-N}" =~ ^[Yy]$ ]] || { info "Aborted."; exit 1; }
else
  ok "All dependencies satisfied — no manual steps needed."
fi

# ============================================================
# INSTALL APP FILES
# ============================================================
section "INSTALLING NETADMIN APPLICATION"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Source:      $SCRIPT_DIR"
info "Destination: $INSTALL_DIR"

# Always ensure destination directories exist regardless of source layout
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/static"

[[ -f "$SCRIPT_DIR/server.py" ]] \
  || die "server.py not found in $SCRIPT_DIR — keep install.sh alongside server.py and static/index.html"

# index.html may be next to install.sh or inside static/ — handle both
if [[ -f "$SCRIPT_DIR/static/index.html" ]]; then
  HTML_SRC="$SCRIPT_DIR/static/index.html"
elif [[ -f "$SCRIPT_DIR/index.html" ]]; then
  HTML_SRC="$SCRIPT_DIR/index.html"
  warn "index.html found next to install.sh (not in static/) — copying it in."
else
  die "index.html not found. Expected at $SCRIPT_DIR/static/index.html"
fi

cp -f "$SCRIPT_DIR/server.py"  "$INSTALL_DIR/server.py"
cp -f "$HTML_SRC"              "$INSTALL_DIR/static/index.html"
ok "Application files installed to $INSTALL_DIR"
ok "  server.py   → $INSTALL_DIR/server.py"
ok "  index.html  → $INSTALL_DIR/static/index.html"

# ============================================================
# LAUNCHER SCRIPT
# ============================================================
section "CREATING LAUNCHER"

LAUNCHER="$HOME/.local/bin/netadmin"
mkdir -p "$HOME/.local/bin"

cat > "$LAUNCHER" <<LAUNCH
#!/usr/bin/env bash
# NetAdmin Portal launcher (generated by install.sh)
# Usage: netadmin [--verbose]
#   --verbose   Enable HTTP request logging in the terminal (off by default)
cd "$INSTALL_DIR"
exec "$PY_EXEC" server.py "\$@"
LAUNCH
chmod +x "$LAUNCHER"
ok "Launcher: $LAUNCHER"

if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  warn "$HOME/.local/bin not in PATH."
  info "Add to your ~/.bashrc:   export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ============================================================
# SYSTEMD SERVICE (OPTIONAL)
# ============================================================
section "SYSTEMD SERVICE (OPTIONAL)"
echo ""
read -rp "  Auto-start on login (systemd user service)? [y/N] " SYSDSVC
if [[ "${SYSDSVC:-N}" =~ ^[Yy]$ ]]; then
  SVCDIR="$HOME/.config/systemd/user"
  mkdir -p "$SVCDIR"
  cat > "$SVCDIR/${SERVICE_NAME}.service" <<SVC
[Unit]
Description=NetAdmin Portal
After=network.target

[Service]
Type=simple
ExecStart=$PY_EXEC $INSTALL_DIR/server.py
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
SVC
  if systemctl --user daemon-reload >/dev/null 2>&1 \
     && systemctl --user enable "${SERVICE_NAME}" >/dev/null 2>&1 \
     && systemctl --user start  "${SERVICE_NAME}" >/dev/null 2>&1; then
    ok "Service '${SERVICE_NAME}' enabled and started."
    info "Control: systemctl --user {start|stop|restart|status} ${SERVICE_NAME}"
  else
    warn "systemd setup failed — run manually: netadmin"
  fi
else
  info "Skipping systemd. Launch with: netadmin"
fi

# ============================================================
# SUDO PRIVILEGES (OPTIONAL)
# ============================================================
section "PRIVILEGE SETUP (OPTIONAL)"
info "nmap OS detection and arp-scan work best with elevated privileges."
echo ""
read -rp "  Add passwordless sudo for nmap and arp-scan? [y/N] " SUDOYES
if [[ "${SUDOYES:-N}" =~ ^[Yy]$ ]]; then
  NMAP_PATH="$(command -v nmap 2>/dev/null || echo /usr/bin/nmap)"
  ARPSCAN_PATH="$(command -v arp-scan 2>/dev/null || echo /usr/sbin/arp-scan)"
  SUDOERS_FILE="/etc/sudoers.d/netadmin"
  printf '%s ALL=(ALL) NOPASSWD: %s, %s\n' "$USER" "$NMAP_PATH" "$ARPSCAN_PATH" \
    | $SUDO tee "$SUDOERS_FILE" >/dev/null 2>&1 \
    && $SUDO chmod 440 "$SUDOERS_FILE" 2>/dev/null \
    && ok "Sudoers rule written: $SUDOERS_FILE" \
    || warn "Could not write sudoers rule — OS detection may be limited."
else
  warn "Skipped. For full OS detection run:  sudo netadmin"
fi

# ============================================================
# DONE
# ============================================================
echo ""
echo -e "${GRN}${BLD}+----------------------------------------------------------+"
echo    "|          NETADMIN PORTAL - INSTALLATION COMPLETE        |"
echo -e "+----------------------------------------------------------+${RST}"
echo ""
ok "Launch command:  ${BLD}netadmin${RST}"
ok "Local URL:       ${BLD}http://localhost:${PORT}${RST}"
LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "${LOCAL_IP:-}" ]] && ok "Network URL:     ${BLD}http://${LOCAL_IP}:${PORT}${RST}"
echo ""
info "The portal auto-scans your network on startup."
echo ""
read -rp "  Launch NetAdmin Portal now? [Y/n] " LAUNCH_NOW
if [[ "${LAUNCH_NOW:-Y}" =~ ^[Yy]$ ]]; then
  echo ""
  info "Starting… open http://localhost:${PORT} in your browser.  Ctrl+C to stop."
  echo ""
  exec "$LAUNCHER"
fi
