#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Installer
#   One-liner: curl -fsSL https://siyarix.dev/install.sh | bash
#
# Supports: Linux (Debian/Ubuntu/Kali/RHEL/Fedora/Arch), macOS, Windows/WSL,
#           Android/Termux, iOS/iSH, HarmonyOS, BSD
# Package managers: pip, pipx, apt, brew, dnf, yum, pacman, ohpm, hpm, snap,
#                   pkg (Termux), apk (Alpine/iSH), winget, choco
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-1.0.0}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
INSTALL_METHOD=""
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
OS_ID=""
OS_LIKE=""

banner() {
  cat << 'EOF'
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v${SIYARIX_VERSION}
EOF
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

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ] && [ -n "$INSTALL_METHOD" ]; then
    warn "Installation failed during ${INSTALL_METHOD} phase."
    warn "Attempting rollback..."
    case "$INSTALL_METHOD" in
      pip|pipx)
        run python3 -m pip uninstall siyarix -y 2>/dev/null || true
        ;;
      brew)
        run brew uninstall siyarix 2>/dev/null || true
        ;;
    esac
  fi
}
trap cleanup EXIT

check_python() {
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
      local maj="${ver%.*}"
      local min="${ver#*.}"
      if [ "$maj" -ge "$PYTHON_MIN_MAJOR" ] && [ "$min" -ge "$PYTHON_MIN_MINOR" ]; then
        PYTHON="$cmd"
        return 0
      fi
    fi
  done
  return 1
}

install_via_pip() {
  INSTALL_METHOD="pip"
  info "Installing via pip..."
  if command -v pipx &>/dev/null; then
    INSTALL_METHOD="pipx"
    run pipx install siyarix 2>/dev/null && return 0
  fi
  INSTALL_METHOD="pip"
  if is_kali_linux; then
    run python3 -m pip install --upgrade --break-system-packages siyarix 2>/dev/null &&
      return 0
    run python3 -m pip install --user siyarix 2>/dev/null && return 0
  fi
  run python3 -m pip install --upgrade siyarix 2>/dev/null ||
    run python3 -m pip install --user siyarix 2>/dev/null ||
    run pip install siyarix 2>/dev/null
}

install_via_brew() {
  INSTALL_METHOD="brew"
  info "Installing via Homebrew..."
  # macOS-specific: ensure Homebrew is on PATH
  if ! command -v brew &>/dev/null; then
    if [ -f "/opt/homebrew/bin/brew" ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -f "/usr/local/bin/brew" ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  run brew install siyarix 2>/dev/null || warn "Homebrew formula not yet in core tap"
}

install_via_apt() {
  INSTALL_METHOD="apt"
  info "Installing via apt (Kali/Debian/Ubuntu)..."
  local repo_url="${SIYARIX_APT_REPO:-https://siyarix.dev/apt}"
  local key_url="${SIYARIX_APT_KEY:-${repo_url}/KEY.gpg}"

  if curl -fsSL "${repo_url}/dists/stable/main/binary-amd64/Packages.gz" &>/dev/null; then
    run curl -fsSL "${key_url}" | run gpg --dearmor -o /usr/share/keyrings/siyarix.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/siyarix.gpg] ${repo_url} stable main" \
      > /etc/apt/sources.list.d/siyarix.list 2>/dev/null || true
    run apt-get update -qq 2>/dev/null
    run apt-get install -y siyarix 2>/dev/null && return 0
  fi

  warn "APT repo not reachable, falling back to pip"
  install_via_pip
}

install_via_dnf() {
  INSTALL_METHOD="dnf"
  info "Installing via dnf/yum..."
  if command -v dnf &>/dev/null; then
    run dnf install -y siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_pacman() {
  INSTALL_METHOD="pacman"
  info "Installing via pacman..."
  if pacman -Si siyarix &>/dev/null; then
    run pacman -S --noconfirm siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_snap() {
  INSTALL_METHOD="snap"
  info "Installing via snap..."
  run snap install siyarix 2>/dev/null && return 0 || true
  install_via_pip
}

install_via_pkg_termux() {
  INSTALL_METHOD="pkg"
  info "Installing via pkg (Termux)..."
  run pkg update -y
  run pkg install -y python clang make libffi openssl binutils
  install_via_pip
}

install_via_apk_ish() {
  INSTALL_METHOD="apk"
  info "Installing via apk (iSH/Alpine)..."
  run apk update
  run apk add python3 py3-pip
  install_via_pip
}

is_kali_linux() {
  [ -f /etc/os-release ] && grep -qi "ID=kali" /etc/os-release 2>/dev/null
}

is_termux() {
  [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]
}

is_ish() {
  [ -n "${TERM_PROGRAM:-}" ] && echo "$TERM_PROGRAM" | grep -qi "ish" 2>/dev/null
}

is_harmonyos() {
  [ -f "/system/etc/param/ohos.para" ] || [ -n "${OHOS_ARCH:-}" ] || (uname -a 2>/dev/null | grep -qi "ohos")
}

is_wsl() {
  uname -r 2>/dev/null | grep -qi "microsoft\|wsl"
}

# --- Detect OS ---
detect_os() {
  if is_termux; then
    echo "termux"
  elif is_ish; then
    echo "ish"
  elif is_harmonyos; then
    echo "harmonyos"
  elif [ "$(uname -s)" = "Linux" ]; then
    if [ -f /etc/os-release ]; then
      . /etc/os-release
      OS_ID="${ID}"
      OS_LIKE="${ID_LIKE:-}"
    fi
    if is_wsl; then
      echo "wsl"
    else
      echo "linux"
    fi
  elif [ "$(uname -s)" = "Darwin" ]; then
    echo "macos"
  else
    case "$(uname -s)" in
      MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
      *) echo "other" ;;
    esac
  fi
}

# --- Main ---
main() {
  banner

  # Parse CLI arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h)
        echo "Usage: curl -fsSL https://siyarix.dev/install.sh | bash [-- [options]]"
        echo ""
        echo "Options:"
        echo "  --version VERSION    Version to install (or set SIYARIX_VERSION)"
        echo "  --dry-run            Simulate installation without changes"
        echo "  --help, -h           Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  SIYARIX_VERSION    Version to install (default: 1.0.0)"
        echo "  SIYARIX_DRY_RUN    Set to 1 for dry-run (default: 0)"
        echo "  SIYARIX_APT_REPO   Custom APT repository URL"
        echo "  SIYARIX_APT_KEY    Custom APT repository GPG key URL"
        exit 0
        ;;
      --dry-run)
        DRY_RUN=1
        info "Dry-run mode enabled"
        shift
        ;;
      --version)
        if [ -z "${2:-}" ]; then
          err "--version requires a version argument"
          exit 1
        fi
        SIYARIX_VERSION="$2"
        shift 2
        ;;
      *)
        err "Unknown option: $1. Use --help for usage."
        exit 1
        ;;
    esac
  done

  # Check if already installed
  if command -v siyarix &>/dev/null; then
    local ver
    ver=$(siyarix --version 2>/dev/null || echo "installed")
    ok "Siyarix already installed: ${ver}"
    info "Run 'pip install --upgrade siyarix' to update"
    return 0
  fi

  # Detect OS
  OS="$(detect_os)"
  info "Detected OS: ${OS}"

  # Platform-specific Python installation
  case "$OS" in
    termux)
      if ! command -v python3 &>/dev/null; then
        warn "Python not found on Termux. Use install_android.sh for full Termux setup."
        info "Quick: pkg install python && pip install siyarix"
        exit 1
      fi
      ;;
    ish)
      if ! command -v python3 &>/dev/null; then
        info "Installing Python via apk..."
        run apk update && run apk add python3 py3-pip
      fi
      ;;
  esac

  # Check Python
  if ! check_python; then
    err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required."
    err "Install from: https://www.python.org/downloads/"
    exit 1
  fi
  ok "Python found: $($PYTHON --version 2>&1)"

  # Check for required tools
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    err "curl or wget is required for download operations."
    exit 1
  fi

  # Platform-specific installation with fallbacks
  case "$OS" in
    termux)
      install_via_pkg_termux
      ;;
    ish)
      install_via_apk_ish
      ;;
    harmonyos)
      if command -v ohpm &>/dev/null; then
        INSTALL_METHOD="ohpm"
        info "HarmonyOS detected. Installing via ohpm..."
        run ohpm install @siyarix/cli 2>/dev/null || install_via_pip
      else
        install_via_pip
      fi
      ;;
    wsl)
      install_via_pip
      WSL_DISPLAY="${DISPLAY:-}"
      if [ -z "$WSL_DISPLAY" ]; then
        warn "WSL: No DISPLAY set. GUI features may not work."
        warn "Set DISPLAY=:0 or install VcXsrv/WSLg."
      fi
      ;;
    linux)
      case "${OS_ID:-}" in
        kali|debian|ubuntu|pop|linuxmint|elementary|zorin)
          install_via_apt
          ;;
        fedora|rhel|centos)
          install_via_dnf
          ;;
        arch|manjaro|endeavouros)
          install_via_pacman
          ;;
        alpine)
          install_via_pip
          ;;
        *)
          install_via_snap
          ;;
      esac
      ;;
    macos)
      if command -v brew &>/dev/null; then
        install_via_brew
      else
        info "Homebrew not found. Installing via pip..."
        install_via_pip
      fi
      # macOS-specific: add to PATH if needed
      if [ -d "$HOME/Library/Python/3.11/bin" ]; then
        export PATH="$HOME/Library/Python/3.11/bin:$PATH"
      fi
      if [ -d "$HOME/Library/Python/3.12/bin" ]; then
        export PATH="$HOME/Library/Python/3.12/bin:$PATH"
      fi
      ;;
    windows)
      install_via_pip
      warn "For better Windows integration, run install.ps1 in PowerShell"
      ;;
    *)
      install_via_pip
      ;;
  esac

  # Verify
  if command -v siyarix &>/dev/null; then
    ok "Siyarix v${SIYARIX_VERSION} installed successfully!"
    info "Run 'siyarix --help' to get started"
  else
    warn "Installation may need manual steps."
    info "Try: pip install siyarix"
  fi
}

main "$@"
