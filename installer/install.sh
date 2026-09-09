#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Installer
#   One-liner: curl -fsSL https://siyarix.github.io/install.sh | bash
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="${SIYARIX_VERSION:-1.0.1}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
INSTALL_METHOD=""
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
OS_ID=""
OS_LIKE=""
PYTHON=""

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
    case "$INSTALL_METHOD" in
      pip|pipx)
        run $PYTHON -m pip uninstall siyarix -y 2>/dev/null || true
        ;;
      brew)
        run brew uninstall siyarix 2>/dev/null || true
        ;;
    esac
  fi
}
trap cleanup EXIT

# --- Python detection ---
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

bootstrap_python() {
  if check_python; then
    return 0
  fi

  info "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ not found. Attempting to install Python..."

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID}"
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
      if [ "$(id -u)" -eq 0 ]; then
        is_root=1
      fi

      local install_cmd=""
      case "${OS_ID:-}" in
        kali|debian|ubuntu|pop|linuxmint|elementary|zorin)
          install_cmd="apt-get update && apt-get install -y python3 python3-pip python3-venv"
          ;;
        fedora|rhel|centos|almalinux|rocky|ol)
          install_cmd="dnf install -y python3 python3-pip"
          ;;
        arch|manjaro|endeavouros|artix|archlabs|garuda)
          install_cmd="pacman -Sy --noconfirm python python-pip"
          ;;
        alpine)
          install_cmd="apk update && apk add python3 py3-pip"
          ;;
      esac

      if [ -n "$install_cmd" ]; then
        if [ "$is_root" -eq 1 ]; then
          eval "run $install_cmd"
        elif command -v sudo &>/dev/null; then
          info "Requesting sudo permissions to install Python..."
          eval "run sudo $install_cmd"
        else
          warn "Please run this installer as root or install Python manually."
          return 1
        fi
      else
        warn "Unsupported package manager. Please install Python manually."
        return 1
      fi
      ;;
    freebsd)
      if [ "$(id -u)" -eq 0 ]; then
        run pkg install -y python311 py311-pip
      elif command -v sudo &>/dev/null; then
        run sudo pkg install -y python311 py311-pip
      fi
      ;;
    openbsd)
      if [ "$(id -u)" -eq 0 ]; then
        run pkg_add python py3-pip
      elif command -v sudo &>/dev/null; then
        run sudo pkg_add python py3-pip
      fi
      ;;
    netbsd)
      if [ "$(id -u)" -eq 0 ]; then
        run pkgin install python311 py311-pip
      elif command -v sudo &>/dev/null; then
        run sudo pkgin install python311 py311-pip
      fi
      ;;
  esac

  if check_python; then
    ok "Python installed successfully: $($PYTHON --version 2>&1)"
    return 0
  fi

  return 1
}

check_and_configure_path() {
  local bin_dir=""
  if [ "$INSTALL_METHOD" = "pipx" ]; then
    bin_dir="$HOME/.local/bin"
  elif [ "$INSTALL_METHOD" = "pip" ]; then
    if [ "$OS" = "macos" ]; then
      local user_base
      user_base=$($PYTHON -c "import site; print(site.USER_BASE)" 2>/dev/null)
      if [ -n "$user_base" ]; then
        bin_dir="${user_base}/bin"
      fi
    else
      bin_dir="$HOME/.local/bin"
    fi
  fi

  if [ -n "$bin_dir" ] && [ -d "$bin_dir" ]; then
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
      info "Adding ${bin_dir} to PATH..."
      local shell_profile=""
      local shell_name
      shell_name=$(basename "$SHELL")
      case "$shell_name" in
        bash)
          if [ -f "$HOME/.bashrc" ]; then
            shell_profile="$HOME/.bashrc"
          elif [ -f "$HOME/.bash_profile" ]; then
            shell_profile="$HOME/.bash_profile"
          else
            shell_profile="$HOME/.profile"
          fi
          ;;
        zsh)
          shell_profile="$HOME/.zshrc"
          ;;
        ksh)
          shell_profile="$HOME/.kshrc"
          ;;
        *)
          shell_profile="$HOME/.profile"
          ;;
      esac

      if [ -n "$shell_profile" ]; then
        if ! grep -q "$bin_dir" "$shell_profile" 2>/dev/null; then
          echo -e "\n# Siyarix PATH\nexport PATH=\"\$PATH:$bin_dir\"" >> "$shell_profile"
          ok "Added PATH export to ${shell_profile}"
          export PATH="$PATH:$bin_dir"
        fi
      fi
    fi
  fi
}


# --- Ensure pip is installed (uses ensurepip, falls back to get-pip.py) ---
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
  local get_pip_url="https://bootstrap.pypa.io/get-pip.py"
  if command -v curl &>/dev/null; then
    curl -fsSL "$get_pip_url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  elif command -v wget &>/dev/null; then
    wget -qO- "$get_pip_url" | $PYTHON &>/dev/null && ok "pip installed via get-pip.py" && return 0
  fi
  err "Failed to install pip. Install it manually: https://pip.pypa.io/en/stable/installation/"
  return 1
}

# --- cryptography build deps ---
# Platforms WITHOUT pre-built cryptography wheels (need Rust + C compiler):
#   - FreeBSD / OpenBSD / NetBSD (no official wheel)
#   - HarmonyOS (no official wheel)

needs_rust_for_cryptography() {
  case "$OS" in
    freebsd|openbsd|netbsd|harmonyos) return 0 ;;
  esac
  # Alpine/iSH: cryptography 42+ provides musl wheels; only need rust if older or edge case
  if [ "$OS" = "ish" ] || [ "$OS_ID" = "alpine" ]; then
    return 1
  fi
  return 1
}

ensure_build_deps() {
  if ! needs_rust_for_cryptography; then
    return 0
  fi
  info "Installing Rust and build tools (required for cryptography on this platform)..."
  case "$OS" in
    freebsd)
      run pkg install -y rust gcc libffi 2>/dev/null
      ;;
    openbsd)
      run pkg_add rust gcc libffi 2>/dev/null
      ;;
    netbsd)
      run pkgin install rust gcc libffi 2>/dev/null
      ;;
    harmonyos)
      warn "Cannot auto-install Rust on HarmonyOS. Install Rust manually: https://rustup.rs"
      return 1
      ;;
  esac
  if command -v rustc &>/dev/null; then
    ok "Rust found: $(rustc --version)"
    return 0
  fi
  warn "Rust install failed. cryptography may fall back to pure-Python or pre-built wheel."
  return 1
}

# --- Systems that enforce PEP 668 (externally-managed-environment) ---
needs_break_system_packages() {
  [ -f /etc/os-release ] || return 1
  local id
  id=$(grep -oP '^ID=.*' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  local like
  like=$(grep -oP '^ID_LIKE=.*' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  for x in kali debian ubuntu pop linuxmint elementary zorin; do
    [ "$id" = "$x" ] && return 0
    echo "$like" | grep -qw "$x" && return 0
  done
  return 1
}

# --- Core pip install with all fallbacks ---
install_via_pip() {
  INSTALL_METHOD="pip"
  info "Installing via pip..."
  ensure_pip || return 1
  ensure_build_deps

  local pip_cmd="$PYTHON -m pip --no-input"

  # Detect active virtual environment
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    info "Active virtual environment detected at ${VIRTUAL_ENV}. Installing Siyarix inside virtual environment..."
    if run $pip_cmd install --upgrade siyarix 2>/dev/null; then
      ok "Siyarix installed inside virtual environment."
      return 0
    fi
  fi

  # Try pipx first (isolated, avoids PEP 668 entirely)
  if command -v pipx &>/dev/null; then
    INSTALL_METHOD="pipx"
    if run pipx install siyarix 2>/dev/null; then
      return 0
    fi
    INSTALL_METHOD="pip"
  fi

  # Strategy 1: --break-system-packages (Kali, Ubuntu 23.04+, Debian 12+)
  if needs_break_system_packages; then
    if run $pip_cmd install --upgrade --break-system-packages siyarix 2>/dev/null; then
      return 0
    fi
  fi

  # Strategy 2: --user install (bypasses system PEP 668)
  if run $pip_cmd install --upgrade --user siyarix 2>/dev/null; then
    return 0
  fi

  # Strategy 3: global install (for root / virtualenv)
  if run $pip_cmd install --upgrade siyarix 2>/dev/null; then
    return 0
  fi

  # Strategy 4: bare pip install as last resort
  if run $pip_cmd install siyarix 2>/dev/null; then
    return 0
  fi

  # Strategy 5: force --break-system-packages if nothing else worked
  if run $pip_cmd install --break-system-packages siyarix 2>/dev/null; then
    return 0
  fi

  return 1
}

# --- Package manager installers ---
install_via_brew() {
  INSTALL_METHOD="brew"
  info "Installing via Homebrew..."
  if ! command -v brew &>/dev/null; then
    if [ -f "/opt/homebrew/bin/brew" ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -f "/usr/local/bin/brew" ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  if command -v brew &>/dev/null; then
    run brew install siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_apt() {
  INSTALL_METHOD="apt"
  info "Installing via apt..."
  local repo_url="${SIYARIX_APT_REPO:-https://siyarix.github.io/apt}"
  local key_url="${SIYARIX_APT_KEY:-${repo_url}/KEY.gpg}"
  if curl -fsSL "${repo_url}/dists/stable/main/binary-amd64/Packages.gz" &>/dev/null; then
    run curl -fsSL "${key_url}" | run gpg --dearmor -o /usr/share/keyrings/siyarix.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/siyarix.gpg] ${repo_url} stable main" \
      > /etc/apt/sources.list.d/siyarix.list 2>/dev/null || true
    run apt-get update -qq 2>/dev/null || true
    run apt-get install -y siyarix 2>/dev/null && return 0
  fi
  install_via_pip
}

install_via_dnf() {
  INSTALL_METHOD="dnf"
  info "Installing via dnf/yum..."
  local dnf_cmd="dnf"
  ! command -v dnf &>/dev/null && dnf_cmd="yum"
  command -v "$dnf_cmd" &>/dev/null && run $dnf_cmd install -y siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_pacman() {
  INSTALL_METHOD="pacman"
  info "Installing via pacman..."
  command -v pacman &>/dev/null && pacman -Si siyarix &>/dev/null && run pacman -S --noconfirm siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_zypper() {
  INSTALL_METHOD="zypper"
  info "Installing via zypper..."
  command -v zypper &>/dev/null && run zypper install -y siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_xbps() {
  INSTALL_METHOD="xbps"
  info "Installing via xbps..."
  command -v xbps-install &>/dev/null && run xbps-install -y siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_emerge() {
  INSTALL_METHOD="emerge"
  info "Installing via emerge..."
  command -v emerge &>/dev/null && run emerge siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_eopkg() {
  INSTALL_METHOD="eopkg"
  info "Installing via eopkg..."
  command -v eopkg &>/dev/null && run eopkg install siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_slackpkg() {
  INSTALL_METHOD="slackpkg"
  info "Installing via slackpkg..."
  command -v slackpkg &>/dev/null && run slackpkg install siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_nix() {
  INSTALL_METHOD="nix"
  info "Installing via nix..."
  command -v nix-env &>/dev/null && run nix-env -iA nixpkgs.siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_swupd() {
  INSTALL_METHOD="swupd"
  info "Installing via swupd..."
  command -v swupd &>/dev/null && run swupd bundle-add siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_snap() {
  INSTALL_METHOD="snap"
  info "Installing via snap..."
  command -v snap &>/dev/null && run snap install siyarix 2>/dev/null && return 0
  install_via_pip
}

install_via_apk_alpine() {
  INSTALL_METHOD="apk"
  info "Installing via apk (Alpine)..."
  run apk update
  run apk add python3 py3-pip
  install_via_pip
}

install_via_pkg_freebsd() {
  INSTALL_METHOD="pkg"
  info "Installing via pkg (FreeBSD)..."
  run pkg update -f
  run pkg install -y python311 py311-pip rust
  install_via_pip
}

install_via_pkg_add_openbsd() {
  INSTALL_METHOD="pkg_add"
  info "Installing via pkg_add (OpenBSD)..."
  run pkg_add python py3-pip rust
  install_via_pip
}

install_via_pkgin_netbsd() {
  INSTALL_METHOD="pkgin"
  info "Installing via pkgin (NetBSD)..."
  run pkgin update
  run pkgin install python311 py311-pip rust
  install_via_pip
}

# --- OS/environment detection ---
is_ish()         { [ -n "${TERM_PROGRAM:-}" ] && echo "$TERM_PROGRAM" | grep -qi "ish" 2>/dev/null; }
is_harmonyos()   { [ -f "/system/etc/param/ohos.para" ] || [ -n "${OHOS_ARCH:-}" ] || (uname -a 2>/dev/null | grep -qi "ohos"); }
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
is_android_container() { [ -f "/system/build.prop" ] || [ -f "/system/etc/build.prop" ] || uname -a 2>/dev/null | grep -qi "android"; }
is_wsl()         { uname -r 2>/dev/null | grep -qi "microsoft\|wsl"; }

detect_os() {
  is_ish && echo "ish" && return
  is_harmonyos && echo "harmonyos" && return
  case "$(uname -s)" in
    Linux)
      if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_LIKE="${ID_LIKE:-}"
      fi
      # ChromeOS detected natively (NOT inside Crostini container)
      is_chromeos && echo "chromeos" && return
      # Android subsystem on ChromeOS (not Termux)
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

# --- Main ---
main() {
  banner

  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h)
        echo "Usage: curl -fsSL https://siyarix.github.io/install.sh | bash [-- [options]]"
        echo ""
        echo "Options:"
        echo "  --version VERSION    Version to install (or set SIYARIX_VERSION)"
        echo "  --dry-run            Simulate installation without changes"
        echo "  --help, -h           Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  SIYARIX_VERSION    Version to install (default: 1.0.1)"
        echo "  SIYARIX_DRY_RUN    Set to 1 for dry-run (default: 0)"
        echo "  SIYARIX_APT_REPO   Custom APT repository URL"
        echo "  SIYARIX_APT_KEY    Custom APT repository GPG key URL"
        exit 0
        ;;
      --dry-run)  DRY_RUN=1; info "Dry-run mode enabled"; shift ;;
      --version)
        [ -z "${2:-}" ] && { err "--version requires a version argument"; exit 1; }
        SIYARIX_VERSION="$2"; shift 2 ;;
      *) err "Unknown option: $1. Use --help for usage."; exit 1 ;;
    esac
  done

  if command -v siyarix &>/dev/null; then
    local ver
    ver=$(siyarix --version 2>/dev/null || echo "installed")
    ok "Siyarix already installed: ${ver}"
    return 0
  fi

  OS="$(detect_os)"
  info "Detected OS: ${OS}"

  # Must have curl or wget
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    err "curl or wget is required."
    exit 1
  fi

  case "$OS" in
    ish)
      if ! command -v python3 &>/dev/null; then
        run apk update
        run apk add python3 py3-pip
      fi
      check_python || { err "Python 3.11+ required"; exit 1; }
      ok "Python found: $($PYTHON --version 2>&1)"
      install_via_pip
      warn "iOS: Some security tools may not be available. Siyarix will operate in registry/offline mode."
      ;;
    harmonyos)
      if command -v ohpm &>/dev/null; then
        INSTALL_METHOD="ohpm"
        info "Installing via ohpm..."
        run ohpm install @siyarix/cli 2>/dev/null || install_via_pip
      else
        install_via_pip
      fi
      ;;
    chromeos)
      info "ChromeOS detected (native shell, not Crostini container)"
      if command -v apt-get &>/dev/null; then
        info "Crostini container detected, installing via apt..."
        install_via_apt
      elif check_python; then
        ok "Python found: $($PYTHON --version 2>&1)"
        install_via_pip
      else
        err "ChromeOS detected without Linux (Crostini) enabled."
        err "Enable it: Settings > Advanced > Developers > Linux development environment"
        err "Alternately install Termux from Google Play to run in Android container."
        info "After enabling Linux, run this installer again."
        exit 1
      fi
      ;;
    android)
      err "Android detected without Termux."
      err "Please install Termux from F-Droid or Google Play, then run the installer inside Termux."
      exit 1
      ;;
    linux|wsl)
      bootstrap_python || { err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required. Please install it manually."; exit 1; }
      ok "Python found: $($PYTHON --version 2>&1)"
      case "${OS_ID:-}" in
        kali|debian|ubuntu|pop|linuxmint|elementary|zorin) install_via_apt ;;
        fedora|rhel|centos|almalinux|rocky|ol)            install_via_dnf ;;
        arch|manjaro|endeavouros|artix|archlabs|garuda)   install_via_pacman ;;
        opensuse*|suse|sles)                               install_via_zypper ;;
        alpine)                                            install_via_apk_alpine ;;
        void)                                              install_via_xbps ;;
        gentoo|funtoo)                                     install_via_emerge ;;
        solus)                                             install_via_eopkg ;;
        slackware)                                         install_via_slackpkg ;;
        nixos)                                             install_via_nix ;;
        clear-linux*)                                      install_via_swupd ;;
        *)
          if   command -v snap &>/dev/null;    then install_via_snap
          elif command -v pacman &>/dev/null;  then install_via_pacman
          elif command -v dnf &>/dev/null;     then install_via_dnf
          elif command -v yum &>/dev/null;     then install_via_dnf
          elif command -v zypper &>/dev/null;  then install_via_zypper
          elif command -v emerge &>/dev/null;  then install_via_emerge
          else install_via_pip
          fi
          ;;
      esac
      [ "$OS" = "wsl" ] && [ -z "${DISPLAY:-}" ] && warn "WSL: No DISPLAY set. GUI features may not work."
      ;;
    macos)
      bootstrap_python || { err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required. Please install it manually."; exit 1; }
      ok "Python found: $($PYTHON --version 2>&1)"
      if command -v brew &>/dev/null; then
        install_via_brew
      else
        info "Homebrew not found. Installing via pip..."
        install_via_pip
      fi
      for pdir in "$HOME/Library/Python/3."{11,12,13}"/bin"; do
        [ -d "$pdir" ] && export PATH="$pdir:$PATH"
      done
      ;;
    freebsd)  install_via_pkg_freebsd ;;
    openbsd)  install_via_pkg_add_openbsd ;;
    netbsd)   install_via_pkgin_netbsd ;;
    *)        install_via_pip ;;
  esac

  check_and_configure_path

  if command -v siyarix &>/dev/null; then
    ok "Siyarix v${SIYARIX_VERSION} installed successfully!"
    info "Run 'siyarix --help' to get started"
  else
    warn "Installation may need manual steps. Try: pip install siyarix"
  fi
}

main "$@"
