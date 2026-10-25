#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# =============================================================================
# Siyarix Docker Entrypoint
# =============================================================================
# - Initializes config if missing
# - Fixes permissions on SIYARIX_HOME
# - Executes the given command or drops into the siyarix CLI
# =============================================================================
set -e

SIYARIX_HOME="${SIYARIX_HOME:-$HOME/.siyarix}"

# ----  Initialise config if it does not exist yet  ---------------------------
# Canonical on-disk settings are settings.toml (see siyarix.config); YAML names
# are retained only for older bind-mounted volumes.
_has_config=0
for _cfg in settings.toml config.yaml config.yml settings.yaml settings.yml; do
    if [ -f "$SIYARIX_HOME/$_cfg" ]; then
        _has_config=1
        break
    fi
done
if [ "$_has_config" -eq 0 ]; then
    echo "[entrypoint] No siyarix config found – running init ..."
    mkdir -p "$SIYARIX_HOME"
    if ! siyarix init --non-interactive; then
        echo "[entrypoint] WARNING: siyarix init failed; continuing with empty home" >&2
    fi
fi
unset _has_config _cfg

# ----  Ensure correct ownership  --------------------------------------------
mkdir -p "$SIYARIX_HOME"
chown -R "$(id -u):$(id -g)" "$SIYARIX_HOME" 2>/dev/null || true

# ----  Execute command (default: siyarix CLI)  ------------------------------
if [ $# -eq 0 ]; then
    echo "[entrypoint] Starting siyarix CLI ..."
    exec siyarix
fi

exec "$@"
