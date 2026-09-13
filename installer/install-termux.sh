#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Enterprise Installer for Android / Termux
#   One-liner: curl -fsSL https://siyarix.github.io/install-termux.sh | bash
#   Mirror:    curl -fsSL https://siyarix.github.io/installer/install-termux.sh | bash
#
# Installs Siyarix AI Cybersecurity Orchestration Agent on Android via Termux.
# Handles native compilation of cryptography with Rust & Clang, PEP 668 bypass,
# storage setup, and shell aliases.
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-1.1.0}"
TERMUX_HOME="${HOME:-/data/data/com.termux/files/home}"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
SILENT="${SIYARIX_SILENT:-0}"
WITH_TOOLS="${SIYARIX_WITH_TOOLS:-0}"
NO_MODIFY_PATH="${SIYARIX_NO_MODIFY_PATH:-0}"
INSTALL_METHOD=""
PYTHON=""
ARCH=""

PACKAGES=(
  python
  python-pip
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
  tar
  gzip
)

OPTIONAL_SECURITY_TOOLS=(
  nmap
  hydra
  sqlmap
)

banner() {
  if [ "$SILENT" = "1" ]; then return 0; fi
  cat << 'EOF'
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v1.1.0
EOF
  echo -e "   Android/Termux Enterprise Installer — \033[36mhttps://siyarix.github.io\033[0m\n"
}

info()  { [ "$SILENT" = "1" ] || echo -e "\033[34m==>\033[0m $*"; }
ok()    { [ "$SILENT" = "1" ] || echo -e "\033[32m  ✓\033[0m $*"; }
warn()  { echo -e "\033[33m  !\033[0m $*" >&2; }
err()   { echo -e "\033[31m  ✗\033[0m $*" >&2; }

run() {
  if [ "$DRY_RUN" = "1" ]; then
    info "[DRY-RUN] Would run: $*"
    return 0
  fi
  "$@"
}

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ] && [ "$DRY_RUN" != "1" ] && [ -n "$INSTALL_METHOD" ]; then
    warn "Termux installation interrupted or failed. Rolling back changes..."
    if [ "$INSTALL_METHOD" = "uv" ] && command -v uv &>/dev/null; then
      run uv tool uninstall siyarix 2>/dev/null || true
    elif [ -n "$PYTHON" ]; then
      run "$PYTHON" -m pip uninstall siyarix -y 2>/dev/null || true
    fi
    err "Installation failed (exit code $exit_code). For support: https://github.com/mufthakherul/siyarix/issues"
  fi
}
trap cleanup EXIT

detect_arch() {
  ARCH=$(uname -m 2>/dev/null || echo "unknown")
  case "$ARCH" in
    aarch64|arm64) ARCH="aarch64" ;;
    armv7l|armv8l|arm) ARCH="arm" ;;
    x86_64|amd64) ARCH="x86_64" ;;
    *) ARCH="$ARCH" ;;
  esac
  echo "$ARCH"
}

detect_termux() {
  [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]
}

check_python() {
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
      if [ -n "$ver" ]; then
        local maj="${ver%.*}"
        local min="${ver#*.}"
        if [ "$maj" -ge 3 ] && [ "$min" -ge 11 ]; then
          PYTHON="$cmd"
          return 0
        fi
      fi
    fi
  done
  return 1
}

setup_storage() {
  if [ ! -d "${TERMUX_HOME}/storage" ] && [ "$DRY_RUN" != "1" ]; then
    info "Requesting Termux shared storage permissions..."
    run termux-setup-storage 2>/dev/null || true
  fi
}

install_system_packages() {
  info "Updating Termux repositories..."
  run pkg update -y || warn "pkg update encountered issues, continuing..."

  info "Installing system build dependencies (clang, rust, openssl, libffi)..."
  run pkg install -y "${PACKAGES[@]}"

  if [ "$WITH_TOOLS" = "1" ]; then
    info "Installing auxiliary security toolchain (nmap, hydra, sqlmap)..."
    for tool in "${OPTIONAL_SECURITY_TOOLS[@]}"; do
      if ! command -v "$tool" &>/dev/null; then
        run pkg install -y "$tool" 2>/dev/null || warn "Could not install optional package: $tool"
      fi
    done
  fi
}

install_siyarix() {
  local pkg="siyarix"
  if [ "$WITH_TOOLS" = "1" ]; then
    pkg="siyarix[all]"
  fi
  if [ "$SIYARIX_VERSION" != "latest" ] && [ -n "$SIYARIX_VERSION" ]; then
    pkg="${pkg}==${SIYARIX_VERSION}"
  fi

  # Attempt 1: uv if available in Termux
  if command -v uv &>/dev/null; then
    info "Installing Siyarix via uv..."
    INSTALL_METHOD="uv"
    if run uv tool install --force "$pkg" 2>/dev/null; then
      ok "Installed Siyarix via uv tool."
      return 0
    fi
  fi

  # Attempt 2: pip with native build isolation flags
  info "Installing Siyarix via pip..."
  INSTALL_METHOD="pip"

  # Ensure pip wheel and setuptools are fresh
  run "$PYTHON" -m pip install --upgrade pip setuptools wheel --no-input --quiet 2>/dev/null || true

  # Try installing with --break-system-packages (PEP 668 compliant for Termux)
  if run "$PYTHON" -m pip install --upgrade --no-build-isolation --break-system-packages "$pkg" 2>/dev/null; then
    ok "Installed Siyarix using pip (--break-system-packages)."
    return 0
  fi

  # Try user-mode install
  if run "$PYTHON" -m pip install --upgrade --no-build-isolation --user "$pkg" 2>/dev/null; then
    ok "Installed Siyarix in user mode."
    return 0
  fi

  # Fallback standard install
  if run "$PYTHON" -m pip install --no-build-isolation "$pkg" 2>/dev/null; then
    ok "Installed Siyarix via standard pip."
    return 0
  fi

  return 1
}

setup_shell_profile() {
  if [ "$NO_MODIFY_PATH" = "1" ]; then
    return 0
  fi

  local rc="${TERMUX_HOME}/.bashrc"
  [ -f "$rc" ] || touch "$rc"

  if ! grep -q "siyarix" "$rc" 2>/dev/null; then
    cat >> "$rc" << 'EOF'

# Siyarix environment
export PATH="$HOME/.local/bin:$PREFIX/bin:$PATH"
alias siyarix='python3 -m siyarix'
EOF
    ok "Added environment and aliases to ${rc}"
  fi
}

show_help() {
  cat << 'EOF'
Siyarix Termux Enterprise Installer

USAGE:
  curl -fsSL https://siyarix.github.io/install-termux.sh | bash
  bash install-termux.sh [OPTIONS]

OPTIONS:
  --version, -v <version>  Install a specific Siyarix release version
  --silent, -s             Unattended silent mode (minimal output)
  --dry-run, -d            Simulate installation without modifying files
  --with-tools             Install auxiliary security binaries (nmap, hydra, sqlmap)
  --no-modify-path         Do not update ~/.bashrc or PATH
  --help, -h               Display this help message

ENVIRONMENT VARIABLES:
  SIYARIX_VERSION, SIYARIX_SILENT, SIYARIX_DRY_RUN, SIYARIX_WITH_TOOLS,
  SIYARIX_NO_MODIFY_PATH
EOF
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version|-v)
        SIYARIX_VERSION="$2"
        shift 2
        ;;
      --silent|-s)
        SILENT="1"
        shift
        ;;
      --dry-run|-d)
        DRY_RUN="1"
        shift
        ;;
      --with-tools)
        WITH_TOOLS="1"
        shift
        ;;
      --no-modify-path)
        NO_MODIFY_PATH="1"
        shift
        ;;
      --help|-h)
        show_help
        exit 0
        ;;
      *)
        err "Unknown parameter: $1"
        show_help
        exit 1
        ;;
    esac
  done

  banner

  if ! detect_termux; then
    err "This installer is specifically built for Android / Termux environments."
    err "For standard Linux or macOS, run: curl -fsSL https://siyarix.github.io/install.sh | bash"
    exit 1
  fi

  local current_arch
  current_arch=$(detect_arch)
  info "Termux Architecture: ${current_arch}"

  # Pre-flight: Check if already installed
  if command -v siyarix &>/dev/null && [ "$DRY_RUN" != "1" ]; then
    local installed_ver
    installed_ver=$(siyarix --version 2>/dev/null || echo "siyarix")
    ok "Siyarix is already installed: ${installed_ver}"
    exit 0
  fi

  setup_storage
  install_system_packages

  check_python || {
    err "Python 3.11+ is required but could not be initialized in Termux."
    exit 1
  }

  ok "Python runtime: $($PYTHON --version 2>&1)"
  if command -v rustc &>/dev/null; then
    ok "Rust compiler: $(rustc --version 2>&1)"
  fi

  install_siyarix
  setup_shell_profile

  # Post-install verification
  if [ "$DRY_RUN" != "1" ]; then
    if "$PYTHON" -c "import siyarix" &>/dev/null; then
      ok "Siyarix import verified successfully."
    else
      warn "Python module verification returned a warning. Check terminal PATH."
    fi
  fi

  if [ "$SILENT" != "1" ]; then
    echo ""
    ok "Siyarix v${SIYARIX_VERSION} installed successfully on Termux!"
    echo -e "\n\033[36mQuick Start:\033[0m"
    echo "  siyarix --help         # Show CLI options"
    echo "  siyarix init           # Interactive setup"
    echo "  siyarix audit          # Run local security audit"
    echo "  siyarix chat           # Launch AI orchestration agent"
    echo ""
    echo "Documentation: https://siyarix.github.io/docs"
    echo "Uninstaller:   curl -fsSL https://siyarix.github.io/uninstall-termux.sh | bash"
  fi
}

main "$@"
