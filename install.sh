#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Installer
#   One-liner: curl -fsSL https://siyarix.dev/install.sh | bash
#
# Supports: Linux (Debian/Ubuntu/Kali/RHEL/Fedora/Arch), macOS, HarmonyOS, BSD
# Package managers: pip, pipx, apt, brew, dnf, yum, pacman, ohpm, hpm, snap
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-0.1.3}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11

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
  info "Installing via pip..."
  if command -v pipx &>/dev/null; then
    pipx install siyarix 2>/dev/null && return 0
  fi
  python3 -m pip install --upgrade siyarix 2>/dev/null ||
    python3 -m pip install --user siyarix 2>/dev/null ||
    pip install siyarix 2>/dev/null
}

install_via_brew() {
  info "Installing via Homebrew..."
  if [ -f "packages/homebrew/siyarix-agent.rb" ]; then
    brew install --formula packages/homebrew/siyarix-agent.rb
  else
    brew install siyarix 2>/dev/null || warn "Homebrew formula not yet in core tap"
  fi
}

install_via_apt() {
  info "Installing via apt (Kali/Debian/Ubuntu)..."
  local repo_url="${SIYARIX_APT_REPO:-https://siyarix.dev/apt}"
  local key_url="${SIYARIX_APT_KEY:-${repo_url}/KEY.gpg}"

  # Try direct install from repo
  if curl -fsSL "${repo_url}/dists/stable/main/binary-amd64/Packages.gz" &>/dev/null; then
    curl -fsSL "${key_url}" | gpg --dearmor -o /usr/share/keyrings/siyarix.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/siyarix.gpg] ${repo_url} stable main" \
      > /etc/apt/sources.list.d/siyarix.list 2>/dev/null || true
    apt-get update -qq 2>/dev/null
    apt-get install -y siyarix 2>/dev/null && return 0
  fi

  # Fallback: pip
  warn "APT repo not reachable, falling back to pip"
  install_via_pip
}

install_via_dnf() {
  info "Installing via dnf/yum..."
  if command -v dnf &>/dev/null; then
    dnf install -y siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_pacman() {
  info "Installing via pacman..."
  if pacman -Si siyarix &>/dev/null; then
    pacman -S --noconfirm siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_snap() {
  info "Installing via snap..."
  snap install siyarix 2>/dev/null && return 0 || true
  install_via_pip
}

install_via_ohpm() {
  if command -v ohpm &>/dev/null; then
    info "Installing via ohpm (OpenHarmony)..."
    ohpm install @mufthakherul/siyarix-agent@"^${SIYARIX_VERSION}" 2>/dev/null
  fi
  install_via_pip
}

install_via_hpm() {
  if command -v hpm &>/dev/null; then
    info "Installing via hpm (HarmonyOS)..."
    hpm install -g @mufthakherul/siyarix-agent 2>/dev/null
  fi
  install_via_pip
}

# --- Detect OS ---
detect_os() {
  case "$(uname -s)" in
    Linux)
      if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_LIKE="${ID_LIKE:-}"
      fi
      echo "linux"
      ;;
    Darwin) echo "macos" ;;
    *) echo "other" ;;
  esac
}

# --- Main ---
main() {
  banner

  # Check if already installed
  if command -v siyarix &>/dev/null; then
    local ver
    ver=$(siyarix --version 2>/dev/null || echo "installed")
    ok "Siyarix already installed: ${ver}"
    info "Run 'siyarix upgrade' or 'pip install --upgrade siyarix' to update"
    return 0
  fi

  # Check Python
  if ! check_python; then
    err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required."
    err "Install from: https://www.python.org/downloads/"
    exit 1
  fi
  ok "Python found: $($PYTHON --version 2>&1)"

  OS="$(detect_os)"
  info "Detected OS: ${OS} (${OS_ID:-unknown})"

  case "$OS" in
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
        *)
          # Try snap first, fallback to pip
          install_via_snap
          ;;
      esac
      ;;
    macos)
      if command -v brew &>/dev/null; then
        install_via_brew
      else
        install_via_pip
      fi
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
