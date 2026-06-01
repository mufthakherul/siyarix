#!/usr/bin/env bash
# =============================================================================
# Siyarix — HarmonyOS / OpenHarmony Installer
# Installs the CLI tool via ohpm (OpenHarmony Package Manager)
# =============================================================================
set -euo pipefail

SIYARIX_VERSION="2.0.0"

echo "==> Installing Siyarix v${SIYARIX_VERSION} for HarmonyOS"

# Check for ohpm
if command -v ohpm &>/dev/null; then
  echo "==> Installing via ohpm..."
  ohpm install @mufthakherul/siyarix@"^${SIYARIX_VERSION}"
  echo "==> ohpm install complete"
fi

# Check for hpm (legacy HarmonyOS package manager)
if command -v hpm &>/dev/null; then
  echo "==> Installing via hpm..."
  hpm install -g @mufthakherul/siyarix
  echo "==> hpm install complete"
fi

# Fallback: ensure Python is available (for Termux / shell environments)
if command -v python3 &>/dev/null; then
  PY_VER=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
  PY_MAJ=${PY_VER%.*}
  PY_MIN=${PY_VER#*.}
  if [ "$PY_MAJ" -ge 3 ] && [ "$PY_MIN" -ge 11 ]; then
    echo "==> Installing via pip (fallback)..."
    python3 -m pip install siyarix 2>/dev/null || python3 -m pip install --user siyarix
  fi
else
  echo "==> WARNING: Python 3.11+ not found."
  echo "    Install Python for HarmonyOS from:"
  echo "    https://www.python.org/downloads/"
fi

echo ""
echo "==> Siyarix v${SIYARIX_VERSION} installation complete!"
echo "    Run 'siyarix --help' to get started."
