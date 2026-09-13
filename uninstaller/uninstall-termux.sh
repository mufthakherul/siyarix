#!/usr/bin/env bash
# =============================================================================
# Siyarix Android / Termux Enterprise Uninstaller
#   One-liner: curl -fsSL https://siyarix.github.io/uninstall-termux.sh | bash
#   Mirror:    curl -fsSL https://siyarix.github.io/installer/uninstall-termux.sh | bash
#
# Removes Siyarix AI Cybersecurity Orchestration Agent from Termux / Android.
# Supports Standard Uninstallation and Deep Dive (forensic-grade trace purge).
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="1.1.0"
DRY_RUN="${SIYARIX_DRY_RUN:-0}"
SILENT="${SIYARIX_SILENT:-0}"
UNINSTALL_MODE=""
AUTO_CONFIRM=0
PYTHON=""

PIP_DETECTED=0
UV_DETECTED=0
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
   AI Cybersecurity Orchestration Agent Uninstaller v1.1.0 (Termux)
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
      info "[DRY-RUN] Would clean: $file"
      return 0
    fi
    info "Cleaning profile: $file"
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
    ok "Profile $file cleaned."
  fi
}

clean_history_file() {
  local hist_file="$1"
  if [ -f "$hist_file" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would clean history: $hist_file"
      return 0
    fi
    local tmp
    tmp=$(mktemp)
    grep -vi "siyarix" "$hist_file" > "$tmp" || true
    mv "$tmp" "$hist_file"
  fi
}

detect_installations() {
  if command -v uv &>/dev/null; then
    if uv tool list 2>/dev/null | grep -qi "siyarix"; then
      UV_DETECTED=1
    fi
  fi

  check_python || true
  if [ -n "$PYTHON" ]; then
    if "$PYTHON" -m pip show siyarix &>/dev/null; then
      PIP_DETECTED=1
    fi
  fi

  if [ -f "pyproject.toml" ] && [ -d ".git" ]; then
    if grep -q "name = \"siyarix\"" pyproject.toml 2>/dev/null; then
      CLONE_DETECTED=1
    fi
  fi
}

perform_regular_uninstall() {
  info "Running Standard Uninstallation..."
  local uninstalled=0

  if [ "$UV_DETECTED" -eq 1 ]; then
    info "Uninstalling via uv tool..."
    run uv tool uninstall siyarix && uninstalled=1
  fi

  if [ "$PIP_DETECTED" -eq 1 ]; then
    info "Uninstalling via pip..."
    run "$PYTHON" -m pip uninstall siyarix -y && uninstalled=1
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
    ok "Siyarix packages removed successfully."
  else
    warn "No Siyarix package detected in Python environment."
  fi
}

perform_deep_dive_uninstall() {
  perform_regular_uninstall

  info "Initiating Deep Dive (Forensic-grade trace purge)..."

  # 1. Config directory
  local siyarix_dir="${SIYARIX_CONFIG_DIR:-${SIYARIX_HOME:-$HOME/.siyarix}}"
  if [ -d "$siyarix_dir" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      info "[DRY-RUN] Would delete config directory: $siyarix_dir"
    else
      info "Deleting configuration, models, database, and logs at: $siyarix_dir"
      rm -rf "$siyarix_dir"
      ok "Deleted $siyarix_dir"
    fi
  fi

  # 2. Keyring credentials
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

  # 3. Shell profiles
  for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    remove_siyarix_from_profile "$profile"
  done

  # 4. History files
  for hist in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history"; do
    clean_history_file "$hist"
  done

  # 5. Termux temporary files
  local termux_tmp="${PREFIX:-/data/data/com.termux/files/usr}/tmp"
  if [ "$DRY_RUN" = "1" ]; then
    info "[DRY-RUN] Would clean temporary files"
  else
    find /tmp -iname "*siyarix*" -exec rm -rf {} + 2>/dev/null || true
    if [ -d "$termux_tmp" ]; then
      find "$termux_tmp" -iname "*siyarix*" -exec rm -rf {} + 2>/dev/null || true
    fi
    ok "Temporary files cleaned."
  fi

  # 6. Pip caches
  if [ -n "$PYTHON" ] && [ "$DRY_RUN" = "0" ]; then
    "$PYTHON" -m pip cache remove siyarix &>/dev/null || true
  fi

  ok "Deep dive uninstallation complete. All traces purged."
}

show_help() {
  cat << 'EOF'
Siyarix Termux Enterprise Uninstaller

USAGE:
  curl -fsSL https://siyarix.github.io/uninstall-termux.sh | bash
  bash uninstall-termux.sh [OPTIONS]

OPTIONS:
  --regular            Normal package uninstall (preserves data and configs)
  --deep, --purge, -p  Forensic purge: delete config, memory DB, logs, keyring, history
  --yes, -y            Auto-confirm all interactive prompts
  --silent, -s         Silent mode, minimal output
  --dry-run, -d        Simulate uninstallation without making changes
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

  if [ "$PIP_DETECTED" -eq 0 ] && [ "$UV_DETECTED" -eq 0 ] && [ "$CLONE_DETECTED" -eq 0 ]; then
    warn "Siyarix was not detected in Termux environment."
    warn "You may still proceed with deep purge to clean leftover configuration files."
  else
    info "Detected Siyarix installations:"
    [ "$UV_DETECTED" -eq 1 ] && ok "  - Installed via uv tool"
    [ "$PIP_DETECTED" -eq 1 ] && ok "  - Installed via pip"
    [ "$CLONE_DETECTED" -eq 1 ] && ok "  - Local Git clone directory"
  fi

  if [ -z "$UNINSTALL_MODE" ]; then
    if [ "$AUTO_CONFIRM" -eq 1 ]; then
      UNINSTALL_MODE="regular"
    else
      echo ""
      echo "Select uninstallation method:"
      echo "  1) Standard   [Remove package, preserve ~/.siyarix configuration]"
      echo "  2) Deep Purge [Forensic cleanup: Purge configs, memory DB, logs, keyring, history]"
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
  ok "Termux uninstallation completed."
}

main "$@"
