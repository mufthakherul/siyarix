#!/usr/bin/env bash
# =============================================================================
# Siyarix Universal Enterprise Uninstaller
#   One-liner: curl -fsSL https://siyarix.github.io/uninstall.sh | bash
#   Mirror:    curl -fsSL https://siyarix.github.io/installer/uninstall.sh | bash
#
# Removes Siyarix AI Cybersecurity Orchestration Agent from Unix systems.
# Supports Standard Uninstallation and Deep Dive (forensic-grade trace purge).
# Package managers: uv, pipx, Homebrew, pip, apt, dnf, pacman, apk, zypper, pkg.
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="1.1.0"
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
SILENT="${SIYARIX_SILENT:-0}"
UNINSTALL_MODE=""
AUTO_CONFIRM=0
PYTHON=""

UV_DETECTED=0
PIX_DETECTED=0
PIP_DETECTED=0
BREW_DETECTED=0
APT_DETECTED=0
DNF_DETECTED=0
PACMAN_DETECTED=0
ZYPPER_DETECTED=0
APK_DETECTED=0
PKG_DETECTED=0
PKG_INFO_DETECTED=0
CLONE_DETECTED=0

banner() {
  if [ "$SILENT" = "1" ]; then return 0; fi
  cat << 'EOF'
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent Enterprise Uninstaller v1.1.0
EOF
  echo -e "   Enterprise Uninstaller — \033[36mhttps://siyarix.github.io\033[0m\n"
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

remove_siyarix_from_profile() {
  local file="$1"
  if [ -f "$file" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would remove Siyarix PATH/alias references from: $file"
      return 0
    fi
    info "Cleaning up shell profile: $file"
    local tmp
    tmp=$(mktemp)

    awk '
    /# Siyarix PATH/ { skip = 2; next }
    /# Siyarix alias/ { skip = 2; next }
    skip > 0 { skip--; next }
    /\.siyarix\/bin/ { next }
    /alias siyarix=/ { next }
    { print }
    ' "$file" > "$tmp"

    mv "$tmp" "$file"
    ok "Shell profile $file cleaned."
  fi
}

clean_system_log() {
  local log_file="$1"
  if [ -f "$log_file" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would purge Siyarix references from log: $log_file"
      return 0
    fi

    if [ -w "$log_file" ]; then
      info "Purging Siyarix log lines from $log_file"
      local tmp
      tmp=$(mktemp)
      grep -vi "siyarix" "$log_file" > "$tmp" || true
      cat "$tmp" > "$log_file"
      rm -f "$tmp"
    elif command -v sudo &>/dev/null; then
      info "Purging Siyarix log lines from $log_file (via sudo)"
      local tmp
      tmp=$(mktemp)
      grep -vi "siyarix" "$log_file" > "$tmp" || true
      sudo dd if="$tmp" of="$log_file" status=none 2>/dev/null || true
      rm -f "$tmp"
    fi
  fi
}

clean_history_file() {
  local hist_file="$1"
  if [ -f "$hist_file" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would purge Siyarix commands from history: $hist_file"
      return 0
    fi

    info "Purging Siyarix commands from history: $hist_file"
    local tmp
    tmp=$(mktemp)
    grep -vi "siyarix" "$hist_file" > "$tmp" || true
    mv "$tmp" "$hist_file"
  fi
}

detect_installations() {
  # 1. uv tool
  if command -v uv &>/dev/null; then
    if uv tool list 2>/dev/null | grep -qi "siyarix"; then
      UV_DETECTED=1
    fi
  fi

  # 2. pipx
  if command -v pipx &>/dev/null; then
    if pipx list 2>/dev/null | grep -qi "siyarix"; then
      PIX_DETECTED=1
    fi
  fi

  # 3. pip
  check_python || true
  if [ -n "$PYTHON" ]; then
    if "$PYTHON" -m pip show siyarix &>/dev/null; then
      PIP_DETECTED=1
    fi
  fi

  # 4. Homebrew
  if command -v brew &>/dev/null; then
    if brew list siyarix &>/dev/null; then
      BREW_DETECTED=1
    fi
  fi

  # 5. Native Linux Package Managers
  if command -v dpkg &>/dev/null; then
    if dpkg -s siyarix &>/dev/null; then APT_DETECTED=1; fi
  fi
  if command -v rpm &>/dev/null; then
    if rpm -q siyarix &>/dev/null; then DNF_DETECTED=1; fi
  fi
  if command -v pacman &>/dev/null; then
    if pacman -Qi siyarix &>/dev/null; then PACMAN_DETECTED=1; fi
  fi
  if command -v apk &>/dev/null; then
    if apk info -e siyarix &>/dev/null; then APK_DETECTED=1; fi
  fi
  if command -v zypper &>/dev/null; then
    if zypper search -i siyarix 2>/dev/null | grep -q "^i.*siyarix"; then ZYPPER_DETECTED=1; fi
  fi
  if command -v pkg &>/dev/null; then
    if pkg info siyarix &>/dev/null; then PKG_DETECTED=1; fi
  fi
  if command -v pkg_info &>/dev/null; then
    if pkg_info siyarix &>/dev/null; then PKG_INFO_DETECTED=1; fi
  fi

  # 6. Local clone
  if [ -f "pyproject.toml" ] && [ -d ".git" ]; then
    if grep -q "name = \"siyarix\"" pyproject.toml 2>/dev/null; then
      CLONE_DETECTED=1
    fi
  fi
}

perform_regular_uninstall() {
  info "Initiating Standard Uninstallation..."
  local uninstalled=0

  if [ "$UV_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via uv tool..."
    run uv tool uninstall siyarix && uninstalled=1
  fi

  if [ "$PIX_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via pipx..."
    run pipx uninstall siyarix && uninstalled=1
  fi

  if [ "$PIP_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via pip..."
    run "$PYTHON" -m pip uninstall siyarix -y && uninstalled=1
  fi

  if [ "$BREW_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via Homebrew..."
    run brew uninstall siyarix && uninstalled=1
  fi

  if [ "$APT_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via apt..."
    if [ "$(id -u)" -eq 0 ]; then
      run apt-get remove --purge siyarix -y && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo apt-get remove --purge siyarix -y && uninstalled=1
    fi
  fi

  if [ "$DNF_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via dnf..."
    if [ "$(id -u)" -eq 0 ]; then
      run dnf remove siyarix -y && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo dnf remove siyarix -y && uninstalled=1
    fi
  fi

  if [ "$PACMAN_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via pacman..."
    if [ "$(id -u)" -eq 0 ]; then
      run pacman -Rns siyarix --noconfirm && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo pacman -Rns siyarix --noconfirm && uninstalled=1
    fi
  fi

  if [ "$ZYPPER_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via zypper..."
    if [ "$(id -u)" -eq 0 ]; then
      run zypper remove -y siyarix && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo zypper remove -y siyarix && uninstalled=1
    fi
  fi

  if [ "$APK_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via apk..."
    if [ "$(id -u)" -eq 0 ]; then
      run apk del siyarix && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo apk del siyarix && uninstalled=1
    fi
  fi

  if [ "$PKG_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via pkg..."
    if [ "$(id -u)" -eq 0 ]; then
      run pkg delete -y siyarix && uninstalled=1
    elif command -v sudo &>/dev/null; then
      run sudo pkg delete -y siyarix && uninstalled=1
    fi
  fi

  if [ "$PKG_INFO_DETECTED" -eq 1 ]; then
    info "Removing Siyarix via pkgin / pkg_delete..."
    if [ "$(id -u)" -eq 0 ]; then
      if command -v pkgin &>/dev/null; then run pkgin remove -y siyarix && uninstalled=1; else run pkg_delete siyarix && uninstalled=1; fi
    elif command -v sudo &>/dev/null; then
      if command -v pkgin &>/dev/null; then run sudo pkgin remove -y siyarix && uninstalled=1; else run sudo pkg_delete siyarix && uninstalled=1; fi
    fi
  fi

  if [ "$CLONE_DETECTED" -eq 1 ]; then
    info "Detected local repository clone. Cleaning build caches..."
    if [ "$DRY_RUN" = "0" ]; then
      rm -rf .venv venv dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache 2>/dev/null || true
      find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
      ok "Build caches and virtual environments cleaned."
    fi
  fi

  if [ "$uninstalled" -eq 1 ]; then
    ok "Siyarix binary packages uninstalled successfully."
  else
    warn "No active package-managed Siyarix installation detected."
  fi
}

perform_deep_dive_uninstall() {
  perform_regular_uninstall

  info "Initiating Deep Dive (Forensic-grade trace purge)..."

  # Step 1: Config, Model, Database, and Plugin Directory
  local siyarix_dir="${SIYARIX_CONFIG_DIR:-${SIYARIX_HOME:-$HOME/.siyarix}}"
  if [ -d "$siyarix_dir" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would delete: $siyarix_dir"
    else
      info "Deleting configuration, models, database, and logs at: $siyarix_dir"
      rm -rf "$siyarix_dir"
      ok "Purged $siyarix_dir"
    fi
  fi

  # Step 2: Keyring Credentials
  if [ "$DRY_RUN" = "1" ]; then
    info "[DRY-RUN] Would purge OS keyring passwords"
  else
    if [ -n "$PYTHON" ]; then
      if "$PYTHON" -c "import keyring" &>/dev/null; then
        "$PYTHON" -c "import keyring; keyring.delete_password('siyarix', 'cred_store_key')" 2>/dev/null || true
        ok "Purged OS keyring entries."
      fi
    fi
  fi

  # Step 3: Shell Profiles and Aliases
  for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.kshrc"; do
    remove_siyarix_from_profile "$profile"
  done

  # Step 4: Shell History Traces
  for hist in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history" "$HOME/.history" "$HOME/.local/share/fish/fish_history"; do
    clean_history_file "$hist"
  done

  # Step 5: System Log References
  for log in "/var/log/dpkg.log" "/var/log/apt/history.log" "/var/log/apt/term.log" "/var/log/pacman.log" "/var/log/dnf.log" "/var/log/yum.log"; do
    clean_system_log "$log"
  done

  # Step 6: Homebrew Logs
  local brew_log_dir="$HOME/Library/Logs/Homebrew/siyarix"
  if [ -d "$brew_log_dir" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would purge: $brew_log_dir"
    else
      rm -rf "$brew_log_dir"
    fi
  fi

  # Step 7: Temporary Files
  if [ "$DRY_RUN" = "1" ]; then
    info "[DRY-RUN] Would purge all /tmp and /var/tmp files matching 'siyarix'"
  else
    find /tmp -iname "*siyarix*" -exec rm -rf {} + 2>/dev/null || true
    find /var/tmp -iname "*siyarix*" -exec rm -rf {} + 2>/dev/null || true
    ok "Temporary files cleaned."
  fi

  # Step 8: Package Manager Tool and Download Caches
  if [ -n "$PYTHON" ]; then
    if [ "$DRY_RUN" = "0" ]; then
      "$PYTHON" -m pip cache remove siyarix &>/dev/null || true
    fi
  fi
  if command -v uv &>/dev/null && [ "$DRY_RUN" = "0" ]; then
    uv cache clean siyarix 2>/dev/null || true
  fi

  ok "Deep dive uninstallation complete. All forensic traces removed."
}

show_help() {
  cat << 'EOF'
Siyarix Universal Enterprise Uninstaller

USAGE:
  curl -fsSL https://siyarix.github.io/uninstall.sh | bash
  bash uninstall.sh [OPTIONS]

OPTIONS:
  --regular            Normal package uninstall only (preserves data & logs)
  --deep, --purge, -p  Forensic purge: delete config, memory, logs, keyring, history
  --yes, -y            Auto-confirm all interactive prompts
  --silent, -s         Silent mode, minimal output
  --dry-run, -d        Simulate uninstall without making filesystem changes
  --help, -h           Show this help message
EOF
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --regular)
        UNINSTALL_MODE="regular"
        shift
        ;;
      --deep|--purge|-p)
        UNINSTALL_MODE="deep"
        shift
        ;;
      --yes|-y)
        AUTO_CONFIRM=1
        shift
        ;;
      --silent|-s)
        SILENT="1"
        shift
        ;;
      --dry-run|-d)
        DRY_RUN="1"
        shift
        ;;
      --help|-h)
        show_help
        exit 0
        ;;
      *)
        err "Unknown option: $1"
        show_help
        exit 1
        ;;
    esac
  done

  banner

  detect_installations

  if [ "$UV_DETECTED" -eq 0 ] && [ "$PIX_DETECTED" -eq 0 ] && [ "$PIP_DETECTED" -eq 0 ] && \
     [ "$BREW_DETECTED" -eq 0 ] && [ "$APT_DETECTED" -eq 0 ] && [ "$DNF_DETECTED" -eq 0 ] && \
     [ "$PACMAN_DETECTED" -eq 0 ] && [ "$ZYPPER_DETECTED" -eq 0 ] && [ "$APK_DETECTED" -eq 0 ] && \
     [ "$PKG_DETECTED" -eq 0 ] && [ "$PKG_INFO_DETECTED" -eq 0 ] && [ "$CLONE_DETECTED" -eq 0 ]; then
    warn "No active package installation of Siyarix was auto-detected."
    warn "You can still run deep purge to delete configuration directories and traces."
  else
    info "Detected Siyarix installations:"
    [ "$UV_DETECTED" -eq 1 ] && ok "  - Installed via uv tool"
    [ "$PIX_DETECTED" -eq 1 ] && ok "  - Installed via pipx"
    [ "$PIP_DETECTED" -eq 1 ] && ok "  - Installed via pip"
    [ "$BREW_DETECTED" -eq 1 ] && ok "  - Installed via Homebrew"
    [ "$APT_DETECTED" -eq 1 ] && ok "  - Installed via apt"
    [ "$DNF_DETECTED" -eq 1 ] && ok "  - Installed via dnf"
    [ "$PACMAN_DETECTED" -eq 1 ] && ok "  - Installed via pacman"
    [ "$ZYPPER_DETECTED" -eq 1 ] && ok "  - Installed via zypper"
    [ "$APK_DETECTED" -eq 1 ] && ok "  - Installed via apk"
    [ "$PKG_DETECTED" -eq 1 ] && ok "  - Installed via FreeBSD pkg"
    [ "$PKG_INFO_DETECTED" -eq 1 ] && ok "  - Installed via OpenBSD/NetBSD pkg"
    [ "$CLONE_DETECTED" -eq 1 ] && ok "  - Local Git clone repository"
  fi

  if [ -z "$UNINSTALL_MODE" ]; then
    if [ "$AUTO_CONFIRM" -eq 1 ]; then
      UNINSTALL_MODE="regular"
    else
      echo ""
      echo "Select uninstallation method:"
      echo "  1) Standard   [Remove binary & package, preserve config and data]"
      echo "  2) Deep Purge [Forensic cleanup: Purge configs, models, memory DB, keyring, history]"
      echo -n "Select option (1 or 2): "

      local choice=""
      read -r choice || choice="1"
      if [ "$choice" = "2" ]; then
        UNINSTALL_MODE="deep"
      else
        UNINSTALL_MODE="regular"
      fi
    fi
  fi

  if [ "$UNINSTALL_MODE" = "deep" ]; then
    perform_deep_dive_uninstall
  else
    perform_regular_uninstall
  fi

  echo ""
  ok "Siyarix uninstallation completed."
}

main "$@"
