#!/usr/bin/env bash
# =============================================================================
# Siyarix Termux Installer
#   One-liner: curl -fsSL https://siyarix.github.io/install-termux.sh | bash
#
# Installs Siyarix AI Cybersecurity Orchestration Agent on Android via Termux.
#
# Termux specifics:
#   - cryptography does NOT ship pre-built wheels for Termux
#   - Requires: rust, clang, make, libffi, openssl, binutils for compilation
#   - pip bootstrapped via ensurepip if missing
#   - PEP 668 enforced on newer Termux → uses --break-system-packages
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-1.0.1}"
TERMUX_HOME="${HOME:-/data/data/com.termux/files/home}"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
PYTHON=""

PACKAGES=(
  python
  python-psutil
  python-cryptography
  rust
  clang
  make
  cmake
  libffi
  openssl
  binutils
  termux-elf-cleaner
  git
  curl
  wget
  openssh
)

SECURITY_TOOLS=(
  nmap
  hydra
  sqlmap
)

banner() {
  echo ""
  echo "   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗"
  echo "   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝"
  echo "   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝"
  echo "   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗"
  echo "   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗"
  echo "   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
  echo "   AI Cybersecurity Orchestration Agent v${SIYARIX_VERSION}"
  echo "   Termux Installer"
  echo ""
}

info()  { echo -e "\033[34m==>\033[0m $*"; }
ok()    { echo -e "\033[32m  ✓\033[0m $*"; }
warn()  { echo -e "\033[33m  !\033[0m $*"; }
err()   { echo -e "\033[31m  ✗\033[0m $*" >&2; }

run() {
  if [ "$DRY_RUN" = "1" ]; then
    info "[DRY-RUN] Would run: $*"
    return 0
  fi
  "$@"
}

detect_termux() {
  [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]
}

check_python() {
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
      local maj="${ver%.*}"
      local min="${ver#*.}"
      if [ "$maj" -ge 3 ] && [ "$min" -ge 11 ]; then
        PYTHON="$cmd"
        return 0
      fi
    fi
  done
  return 1
}

ensure_pip() {
  if $PYTHON -m pip --version &>/dev/null; then
    return 0
  fi
  info "pip not found. Installing pip..."
  if $PYTHON -m ensurepip --upgrade &>/dev/null; then
    ok "pip installed via ensurepip"
    return 0
  fi
  info "ensurepip failed, trying get-pip.py..."
  local url="https://bootstrap.pypa.io/get-pip.py"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  elif command -v wget &>/dev/null; then
    wget -qO- "$url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  fi
  err "Failed to install pip. Install manually: https://pip.pypa.io/en/stable/installation/"
  return 1
}

setup_storage() {
  if [ ! -d "${HOME}/storage" ]; then
    info "Requesting Termux storage permissions..."
    run termux-setup-storage 2>/dev/null || true
  fi
}

setup_alias() {
  local rc="${HOME}/.bashrc"
  [ ! -f "$rc" ] && touch "$rc"
  if ! grep -q "siyarix" "$rc" 2>/dev/null; then
    cat >> "$rc" << 'EOF'

# Siyarix alias
alias siyarix='python3 -m siyarix'
EOF
    ok "Added siyarix alias to ~/.bashrc"
  fi
}

install_system_packages() {
  info "Updating package lists..."
  run pkg update -y
  run pkg upgrade -y

  info "Installing build dependencies..."
  run pkg install -y "${PACKAGES[@]}"

  info "Installing optional security tools (nmap, hydra, sqlmap)..."
  for tool in "${SECURITY_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      run pkg install -y "$tool" 2>/dev/null || warn "Failed to install $tool (optional)"
    fi
  done
}

install_siyarix() {
  info "Installing Siyarix via pip..."
  ensure_pip || return 1

  run $PYTHON -m pip install --upgrade pip setuptools wheel --no-input

  if run $PYTHON -m pip install --upgrade --break-system-packages siyarix 2>/dev/null; then
    return 0
  fi

  if run $PYTHON -m pip install --upgrade --user siyarix 2>/dev/null; then
    return 0
  fi

  if run $PYTHON -m pip install siyarix 2>/dev/null; then
    return 0
  fi

  return 1
}

main() {
  banner

  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h)
        echo "Usage: bash install-termux.sh [options]"
        echo ""
        echo "Options:"
        echo "  --dry-run       Simulate installation without changes"
        echo "  --help, -h      Show this help message"
        exit 0
        ;;
      --dry-run) DRY_RUN=1; shift ;;
      *) err "Unknown option: $1"; exit 1 ;;
    esac
  done

  if ! detect_termux; then
    err "This script is for Android/Termux only."
    err "Install Termux from F-Droid: https://f-droid.org/packages/com.termux/"
    err "Or from GitHub: https://github.com/termux/termux-app/releases"
    exit 1
  fi
  ok "Termux environment detected"

  if command -v siyarix &>/dev/null; then
    local ver
    ver=$(siyarix --version 2>/dev/null || echo "installed")
    ok "Siyarix already installed: ${ver}"
    return 0
  fi

  setup_storage
  install_system_packages

  check_python || { err "Failed to install Python."; exit 1; }
  ok "Python: $($PYTHON --version 2>&1)"
  ok "Rust: $(rustc --version 2>&1)"
  ok "Cargo: $(cargo --version 2>&1)"

  install_siyarix
  setup_alias

  if $PYTHON -c "import siyarix; print(siyarix.__version__)" &>/dev/null; then
    local ver
    ver=$($PYTHON -c "import siyarix; print(siyarix.__version__)")
    ok "Siyarix v${ver} installed successfully!"
    info "Config: ${TERMUX_HOME}/.siyarix"
    info "Run:    siyarix --help"
    info "Or:     python3 -m siyarix --help"
  else
    err "Installation verification failed."
    exit 1
  fi
}

main "$@"
