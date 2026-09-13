#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Enterprise Installer
#   One-liner: curl -fsSL https://siyarix.github.io/install.sh | bash
#   Mirror:    curl -fsSL https://siyarix.github.io/installer/install.sh | bash
#
# Supports: Linux (all major distros), macOS (Apple Silicon & Intel),
#           FreeBSD/OpenBSD/NetBSD, ChromeOS, iOS (iSH), WSL1/WSL2, HarmonyOS.
# Package managers: uv, pipx, Homebrew, pip, apt, dnf, pacman, apk, zypper, pkg.
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-1.1.0}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
INSTALL_METHOD="${SIYARIX_METHOD:-}"
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
SILENT="${SIYARIX_SILENT:-0}"
WITH_TOOLS="${SIYARIX_WITH_TOOLS:-0}"
NO_MODIFY_PATH="${SIYARIX_NO_MODIFY_PATH:-0}"
TARGET_DIR="${SIYARIX_TARGET_DIR:-}"
OS_ID=""
OS_LIKE=""
PYTHON=""
ARCH=""

banner() {
  if [ "$SILENT" = "1" ]; then
    return 0
  fi
  cat << 'EOF'
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v1.1.0
EOF
  echo -e "   Enterprise Installer — \033[36mhttps://siyarix.github.io\033[0m\n"
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
    warn "Installation interrupted or encountered an error. Rolling back changes..."
    case "$INSTALL_METHOD" in
      uv)
        run uv tool uninstall siyarix 2>/dev/null || true
        ;;
      pipx)
        run pipx uninstall siyarix 2>/dev/null || true
        ;;
      pip)
        if [ -n "$PYTHON" ]; then
          run $PYTHON -m pip uninstall siyarix -y 2>/dev/null || true
        fi
        ;;
      brew)
        run brew uninstall siyarix 2>/dev/null || true
        ;;
    esac
    err "Installation failed (exit code $exit_code). For help, visit https://github.com/mufthakherul/siyarix/issues"
  fi
}
trap cleanup EXIT

# --- Architecture Detection ---
detect_arch() {
  local m
  m=$(uname -m 2>/dev/null || echo "unknown")
  case "$m" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="arm" ;;
    riscv64) ARCH="riscv64" ;;
    i386|i686) ARCH="x86" ;;
    *) ARCH="$m" ;;
  esac
  echo "$ARCH"
}

# --- Python detection ---
check_python() {
  for cmd in python3 python python3.13 python3.12 python3.11; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
      if [ -n "$ver" ]; then
        local maj="${ver%.*}"
        local min="${ver#*.}"
        if [ "$maj" -ge "$PYTHON_MIN_MAJOR" ] && [ "$min" -ge "$PYTHON_MIN_MINOR" ]; then
          PYTHON="$cmd"
          return 0
        fi
      fi
    fi
  done
  return 1
}

bootstrap_python() {
  if check_python; then
    return 0
  fi

  info "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ not found. Bootstrapping system Python..."

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
  fi

  case "$OS" in
    macos)
      if command -v brew &>/dev/null; then
        run brew install python@3.12 2>/dev/null
      else
        warn "Homebrew not found. Please install Python manually: https://www.python.org/downloads/"
        return 1
      fi
      ;;
    linux|wsl)
      local is_root=0
      [ "$(id -u)" -eq 0 ] && is_root=1

      local install_cmd=""
      case "${OS_ID:-}" in
        kali|debian|ubuntu|pop|linuxmint|elementary|zorin|parrot)
          install_cmd="apt-get update -y && apt-get install -y python3 python3-pip python3-venv python3-full"
          ;;
        fedora|rhel|centos|almalinux|rocky|ol)
          install_cmd="dnf install -y python3 python3-pip"
          ;;
        arch|manjaro|endeavouros|artix|archlabs|garuda)
          install_cmd="pacman -Sy --noconfirm python python-pip python-virtualenv"
          ;;
        alpine)
          install_cmd="apk update && apk add python3 py3-pip python3-dev"
          ;;
        opensuse*|suse|sles)
          install_cmd="zypper refresh && zypper install -y python311 python311-pip || zypper install -y python3 python3-pip"
          ;;
        void)
          install_cmd="xbps-install -Sy python3 python3-pip"
          ;;
      esac

      if [ -n "$install_cmd" ]; then
        if [ "$is_root" -eq 1 ]; then
          eval "run $install_cmd"
        elif command -v sudo &>/dev/null; then
          info "Requesting sudo privileges to install Python dependencies..."
          eval "run sudo $install_cmd"
        else
          warn "Root/sudo privileges required to install Python packages."
          return 1
        fi
      else
        warn "Unsupported distribution package manager. Please install Python 3.11+ manually."
        return 1
      fi
      ;;
    freebsd)
      local cmd="pkg install -y python311 py311-pip"
      [ "$(id -u)" -eq 0 ] && run $cmd || run sudo $cmd
      ;;
    openbsd)
      local cmd="pkg_add python py3-pip"
      [ "$(id -u)" -eq 0 ] && run $cmd || run sudo $cmd
      ;;
    netbsd)
      local cmd="pkgin -y install python311 py311-pip"
      [ "$(id -u)" -eq 0 ] && run $cmd || run sudo $cmd
      ;;
  esac

  if check_python; then
    ok "Python installed successfully: $($PYTHON --version 2>&1)"
    return 0
  fi

  return 1
}

# --- Shell Profile & PATH Configuration ---
check_and_configure_path() {
  [ "$NO_MODIFY_PATH" = "1" ] && return 0

  local bin_dirs=()
  [ -d "$HOME/.local/bin" ] && bin_dirs+=("$HOME/.local/bin")
  [ -d "$HOME/.cargo/bin" ] && bin_dirs+=("$HOME/.cargo/bin")

  if [ "$OS" = "macos" ]; then
    for pdir in "$HOME/Library/Python/3."{11,12,13,14}"/bin"; do
      [ -d "$pdir" ] && bin_dirs+=("$pdir")
    done
    [ -d "/opt/homebrew/bin" ] && bin_dirs+=("/opt/homebrew/bin")
  fi

  local shell_name
  shell_name=$(basename "${SHELL:-bash}")
  local profiles=()

  case "$shell_name" in
    bash)
      [ -f "$HOME/.bashrc" ] && profiles+=("$HOME/.bashrc")
      [ -f "$HOME/.bash_profile" ] && profiles+=("$HOME/.bash_profile")
      [ -f "$HOME/.profile" ] && profiles+=("$HOME/.profile")
      ;;
    zsh)
      [ -f "$HOME/.zshrc" ] && profiles+=("$HOME/.zshrc")
      [ -f "$HOME/.zprofile" ] && profiles+=("$HOME/.zprofile")
      ;;
    fish)
      [ -f "$HOME/.config/fish/config.fish" ] && profiles+=("$HOME/.config/fish/config.fish")
      ;;
    *)
      [ -f "$HOME/.profile" ] && profiles+=("$HOME/.profile")
      ;;
  esac

  # Fallback profile if none matched
  if [ ${#profiles[@]} -eq 0 ]; then
    if [ -f "$HOME/.bashrc" ]; then
      profiles+=("$HOME/.bashrc")
    else
      profiles+=("$HOME/.profile")
    fi
  fi

  for bdir in "${bin_dirs[@]}"; do
    if [[ ":$PATH:" != *":$bdir:"* ]]; then
      export PATH="$bdir:$PATH"
      for prof in "${profiles[@]}"; do
        if [ -f "$prof" ] && ! grep -q "$bdir" "$prof" 2>/dev/null; then
          if [ "$shell_name" = "fish" ]; then
            echo -e "\n# Siyarix PATH\nfish_add_path $bdir" >> "$prof"
          else
            echo -e "\n# Siyarix PATH\nexport PATH=\"\$PATH:$bdir\"" >> "$prof"
          fi
          ok "Added $bdir to PATH in $prof"
        fi
      done
    fi
  done
}

# --- Ensure pip is installed ---
ensure_pip() {
  if $PYTHON -m pip --version &>/dev/null; then
    return 0
  fi
  info "pip not found. Bootstrapping pip..."
  if $PYTHON -m ensurepip --upgrade &>/dev/null; then
    ok "pip bootstrapped via ensurepip"
    return 0
  fi
  info "Trying get-pip.py bootstrap..."
  local get_pip_url="https://bootstrap.pypa.io/get-pip.py"
  if command -v curl &>/dev/null; then
    curl -fsSL "$get_pip_url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  elif command -v wget &>/dev/null; then
    wget -qO- "$get_pip_url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  fi
  warn "Could not bootstrap pip automatically. Trying system packages..."
  return 1
}

# --- Installation Methods ---

# 1. uv installer (High-Speed, Isolated, Modern)
install_via_uv() {
  INSTALL_METHOD="uv"
  info "Installing Siyarix using uv (high-speed isolated environment)..."
  if command -v uv &>/dev/null; then
    local uv_flags=""
    [ -n "$TARGET_DIR" ] && uv_flags="--directory $TARGET_DIR"
    if run uv tool install --force $uv_flags "siyarix==${SIYARIX_VERSION}" 2>/dev/null || run uv tool install --force $uv_flags siyarix 2>/dev/null; then
      ok "Installed Siyarix via uv tool!"
      return 0
    fi
  fi
  return 1
}

# 2. pipx installer (Standard Isolated Virtual Environments)
install_via_pipx() {
  INSTALL_METHOD="pipx"
  info "Installing Siyarix using pipx (isolated environment)..."
  if command -v pipx &>/dev/null; then
    if run pipx install --force "siyarix==${SIYARIX_VERSION}" 2>/dev/null || run pipx install --force siyarix 2>/dev/null; then
      ok "Installed Siyarix via pipx!"
      return 0
    fi
  fi
  return 1
}

# 3. Homebrew installer (macOS & Linuxbrew)
install_via_brew() {
  INSTALL_METHOD="brew"
  info "Installing Siyarix using Homebrew..."
  if ! command -v brew &>/dev/null; then
    if [ -f "/opt/homebrew/bin/brew" ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -f "/usr/local/bin/brew" ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  if command -v brew &>/dev/null; then
    if run brew install siyarix 2>/dev/null; then
      ok "Installed Siyarix via Homebrew!"
      return 0
    fi
  fi
  return 1
}

# 4. pip installer (Universal Fallback with PEP 668 Handling)
install_via_pip() {
  INSTALL_METHOD="pip"
  info "Installing Siyarix via pip..."
  ensure_pip || true

  local pip_cmd="$PYTHON -m pip --no-input"
  local pkg_spec="siyarix==${SIYARIX_VERSION}"

  # Check active virtual environment
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    info "Active virtual environment detected ($VIRTUAL_ENV). Installing inside venv..."
    if run $pip_cmd install --upgrade "$pkg_spec" 2>/dev/null || run $pip_cmd install --upgrade siyarix 2>/dev/null; then
      ok "Siyarix installed inside active virtual environment."
      return 0
    fi
  fi

  # Strategy A: pip with --user and --break-system-packages (for PEP 668 systems like Kali/Debian 12/Ubuntu 23+)
  if run $pip_cmd install --upgrade --user --break-system-packages "$pkg_spec" 2>/dev/null || run $pip_cmd install --upgrade --user --break-system-packages siyarix 2>/dev/null; then
    ok "Installed Siyarix for current user."
    return 0
  fi

  # Strategy B: pip with standard --user
  if run $pip_cmd install --upgrade --user "$pkg_spec" 2>/dev/null || run $pip_cmd install --upgrade --user siyarix 2>/dev/null; then
    ok "Installed Siyarix for current user."
    return 0
  fi

  # Strategy C: system pip with --break-system-packages (if running as root or container)
  if run $pip_cmd install --upgrade --break-system-packages "$pkg_spec" 2>/dev/null || run $pip_cmd install --upgrade --break-system-packages siyarix 2>/dev/null; then
    ok "Installed Siyarix globally."
    return 0
  fi

  # Strategy D: bare pip install
  if run $pip_cmd install "$pkg_spec" 2>/dev/null || run $pip_cmd install siyarix 2>/dev/null; then
    ok "Installed Siyarix."
    return 0
  fi

  return 1
}

# --- Optional Security Tools Installer ---
install_security_tools() {
  [ "$WITH_TOOLS" = "1" ] || return 0
  info "Installing foundational security tools (nmap, curl, whois, dig)..."

  local is_root=0
  [ "$(id -u)" -eq 0 ] && is_root=1

  case "$OS" in
    macos)
      if command -v brew &>/dev/null; then
        run brew install nmap whois bind curl httpx 2>/dev/null || true
      fi
      ;;
    linux|wsl)
      local pm_cmd=""
      case "${OS_ID:-}" in
        kali|debian|ubuntu|pop|linuxmint|parrot)
          pm_cmd="apt-get install -y nmap whois dnsutils curl"
          ;;
        fedora|rhel|centos|almalinux|rocky)
          pm_cmd="dnf install -y nmap whois bind-utils curl"
          ;;
        arch|manjaro|endeavouros)
          pm_cmd="pacman -Sy --noconfirm nmap whois bind curl"
          ;;
        alpine)
          pm_cmd="apk add nmap whois bind-tools curl"
          ;;
      esac
      if [ -n "$pm_cmd" ]; then
        if [ "$is_root" -eq 1 ]; then
          eval "run $pm_cmd 2>/dev/null || true"
        elif command -v sudo &>/dev/null; then
          eval "run sudo $pm_cmd 2>/dev/null || true"
        fi
      fi
      ;;
  esac
  ok "Security tools setup completed."
}

# --- OS & Environment Detection ---
is_ish()               { [ -n "${TERM_PROGRAM:-}" ] && echo "$TERM_PROGRAM" | grep -qi "ish" 2>/dev/null; }
is_harmonyos()         { [ -f "/system/etc/param/ohos.para" ] || [ -n "${OHOS_ARCH:-}" ] || (uname -a 2>/dev/null | grep -qi "ohos"); }
is_chromeos() {
  if [ -f /etc/os-release ]; then
    local id
    id=$(grep -oP '^ID=.*' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    [ "$id" = "chromeos" ] || [ "$id" = "chromiumos" ] && return 0
  fi
  [ -f /etc/lsb-release ] && grep -qi "chromeos" /etc/lsb-release 2>/dev/null && return 0
  [ -f /dev/.cros_milestone ] && return 0
  return 1
}
is_android_container() { [ -f "/system/build.prop" ] || [ -f "/system/etc/build.prop" ] || (uname -a 2>/dev/null | grep -qi "android"); }
is_wsl()               { uname -r 2>/dev/null | grep -qi "microsoft\|wsl"; }

detect_os() {
  is_ish && echo "ish" && return
  is_harmonyos && echo "harmonyos" && return
  case "$(uname -s)" in
    Linux)
      if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_LIKE="${ID_LIKE:-}"
      fi
      is_chromeos && echo "chromeos" && return
      is_android_container && echo "android" && return
      is_wsl && echo "wsl" || echo "linux"
      ;;
    Darwin)    echo "macos" ;;
    FreeBSD)   echo "freebsd" ;;
    OpenBSD)   echo "openbsd" ;;
    NetBSD)    echo "netbsd" ;;
    *)         echo "other" ;;
  esac
}

show_help() {
  cat << EOF
Siyarix Universal Enterprise Installer

Usage:
  curl -fsSL https://siyarix.github.io/install.sh | bash [options]

Options:
  -h, --help               Display this help guide and exit
  -s, -y, --silent         Headless unattended mode for CI/CD & Docker
  --dry-run                Simulate execution without modifying the system
  --version <ver>          Install a specific Siyarix release (e.g. 1.1.0)
  --with-tools             Automatically install core security utilities (nmap, curl, whois, dig)
  --no-modify-path         Do not append binary directories to shell profiles
  --target-dir <dir>       Specify custom directory destination
  --method <name>          Force install method: uv, pipx, brew, or pip

Environment Variables:
  SIYARIX_VERSION          Pinned Siyarix version (default: 1.1.0)
  SIYARIX_SILENT           Set to 1 for silent / unattended mode
  SIYARIX_DRY_RUN          Set to 1 to simulate actions
  SIYARIX_WITH_TOOLS       Set to 1 to auto-install security tools
  SIYARIX_NO_MODIFY_PATH   Set to 1 to skip shell profile modifications
  SIYARIX_METHOD           Override package manager method

Examples:
  # Quick installation (Recommended)
  curl -fsSL https://siyarix.github.io/install.sh | bash

  # Unattended CI/CD install with tools
  curl -fsSL https://siyarix.github.io/install.sh | bash -s -- --silent --with-tools

  # High-speed installation via uv
  curl -fsSL https://siyarix.github.io/install.sh | bash -s -- --method uv
EOF
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_help
        exit 0
        ;;
      -s|-y|--silent|--non-interactive)
        SILENT=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        info "Dry-run mode activated (simulating execution)."
        shift
        ;;
      --with-tools)
        WITH_TOOLS=1
        shift
        ;;
      --no-modify-path)
        NO_MODIFY_PATH=1
        shift
        ;;
      --target-dir)
        [ -z "${2:-}" ] && { err "--target-dir requires a path"; exit 1; }
        TARGET_DIR="$2"
        shift 2
        ;;
      --version)
        [ -z "${2:-}" ] && { err "--version requires a version argument"; exit 1; }
        SIYARIX_VERSION="$2"
        shift 2
        ;;
      --method)
        [ -z "${2:-}" ] && { err "--method requires uv, pipx, brew, or pip"; exit 1; }
        INSTALL_METHOD="$2"
        shift 2
        ;;
      *)
        warn "Unknown option: $1 (ignoring)"
        shift
        ;;
    esac
  done

  banner
  OS="$(detect_os)"
  ARCH="$(detect_arch)"
  info "Detected Environment: OS=\033[36m${OS}\033[0m Architecture=\033[36m${ARCH}\033[0m"

  # If user forced a specific method
  if [ -n "$INSTALL_METHOD" ]; then
    bootstrap_python || true
    case "$INSTALL_METHOD" in
      uv)   install_via_uv || install_via_pip ;;
      pipx) install_via_pipx || install_via_pip ;;
      brew) install_via_brew || install_via_pip ;;
      pip)  install_via_pip ;;
      *)    err "Unsupported method: $INSTALL_METHOD"; exit 1 ;;
    esac
  else
    # Auto-detection cascade
    # Priority 1: uv (Fastest, isolated, zero-conflict)
    if command -v uv &>/dev/null && install_via_uv; then
      :
    # Priority 2: pipx (Isolated virtual environment)
    elif command -v pipx &>/dev/null && install_via_pipx; then
      :
    # Priority 3: Homebrew (macOS native)
    elif [ "$OS" = "macos" ] && command -v brew &>/dev/null && install_via_brew; then
      :
    # Priority 4: Platform native / Python bootstrap + pip
    else
      bootstrap_python || {
        err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required. Please install it manually: https://python.org"
        exit 1
      }
      install_via_pip
    fi
  fi

  check_and_configure_path
  install_security_tools

  # Post-installation health verification
  if command -v siyarix &>/dev/null; then
    local installed_ver
    installed_ver=$(siyarix --version 2>/dev/null || echo "v${SIYARIX_VERSION}")
    ok "Siyarix installed successfully (\033[32m${installed_ver}\033[0m)!"
    if [ "$SILENT" != "1" ]; then
      echo ""
      echo -e "\033[1;36mNext Steps:\033[0m"
      echo -e "  • Verify CLI:       \033[33msiyarix --help\033[0m"
      echo -e "  • Setup Config:     \033[33msiyarix init\033[0m"
      echo -e "  • Quick Scan:       \033[33msiyarix scan 127.0.0.1\033[0m"
      echo -e "  • Plugins Hub:      \033[33msiyarix plugin search\033[0m"
      echo ""
      if [ "$NO_MODIFY_PATH" != "1" ]; then
        echo -e "\033[2mNote: If 'siyarix' is not recognized, restart your terminal or run: source ~/.bashrc (or ~/.zshrc)\033[0m\n"
      fi
    fi
  else
    warn "Installation finished, but 'siyarix' binary was not immediately found in active PATH."
    warn "Run: export PATH=\"\$PATH:\$HOME/.local/bin\" or restart your terminal."
  fi
}

main "$@"
