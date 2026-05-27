#!/usr/bin/env pwsh
# =============================================================================
# Siyarix Universal Installer for Windows
#   One-liner: irm https://siyarix.dev/install.ps1 | iex
#
# Supports: Windows 10/11, Windows Server
# Package managers: pip, winget, chocolatey, npm
# =============================================================================
$__script_version = "0.1.3"

function Write-Banner {
  @"
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v$__script_version
"@
  Write-Host "`nSiyarix — AI Cybersecurity Orchestration Agent`n" -ForegroundColor Cyan
}

function Write-Info  { Write-Host "==>" -ForegroundColor Blue -NoNewline; Write-Host " $args" }
function Write-Ok    { Write-Host "  ✓" -ForegroundColor Green -NoNewline; Write-Host " $args" }
function Write-Warn  { Write-Host "  !" -ForegroundColor Yellow -NoNewline; Write-Host " $args" }
function Write-Err   { Write-Host "  ✗" -ForegroundColor Red -NoNewline; Write-Host " $args" }

function Test-Python {
  try {
    $ver = python --version 2>&1
    if ($ver -match "(\d+)\.(\d+)") {
      $maj = [int]$Matches[1]
      $min = [int]$Matches[2]
      return ($maj -ge 3 -and $min -ge 11)
    }
  } catch {}
  try {
    $ver = python3 --version 2>&1
    if ($ver -match "(\d+)\.(\d+)") {
      $maj = [int]$Matches[1]
      $min = [int]$Matches[2]
      return ($maj -ge 3 -and $min -ge 11)
    }
  } catch {}
  return $false
}

function Install-ViaPip {
  Write-Info "Installing via pip..."
  try {
    python -m pip install --upgrade pip
    python -m pip install siyarix
    return $true
  } catch {
    try {
      python -m pip install --user siyarix
      return $true
    } catch {
      return $false
    }
  }
}

function Install-ViaWinget {
  Write-Info "Installing via winget..."
  try {
    winget install Mufthakherul.Siyarix --accept-package-agreements --silent
    return $true
  } catch {
    return $false
  }
}

function Install-ViaChoco {
  Write-Info "Installing via Chocolatey..."
  try {
    choco install siyarix -y
    return $true
  } catch {
    return $false
  }
}

function Install-ViaNpm {
  Write-Info "Installing via npm..."
  try {
    npm install -g @mufthakherul/siyarix-agent
    return $true
  } catch {
    return $false
  }
}

function Install-ViaPipx {
  Write-Info "Installing via pipx..."
  try {
    pipx install siyarix
    return $true
  } catch {
    return $false
  }
}

# --- Main ---
function Main {
  Write-Banner

  # Already installed?
  try {
    $ver = & siyarix --version 2>&1
    Write-Ok "Siyarix already installed: $ver"
    Write-Info "Run 'pip install --upgrade siyarix' to update"
    return 0
  } catch {}

  # Check Python
  if (-not (Test-Python)) {
    Write-Err "Python 3.11+ is required."
    Write-Err "Download from: https://www.python.org/downloads/"
    Write-Info "After installing Python, re-run this installer."
    return 1
  }
  Write-Ok "Python found: $(python --version 2>&1)"

  # Try installers in order of preference
  $installers = @(
    { Install-ViaPipx }.GetNewClosure(),
    { Install-ViaPip }.GetNewClosure(),
    { Install-ViaWinget }.GetNewClosure(),
    { Install-ViaChoco }.GetNewClosure(),
    { Install-ViaNpm }.GetNewClosure()
  )

  $installed = $false
  foreach ($installer in $installers) {
    try {
      $result = & $installer
      if ($result) { $installed = $true; break }
    } catch { continue }
  }

  if ($installed) {
    Write-Ok "Siyarix v$__script_version installed successfully!"
    Write-Info "Run 'siyarix --help' to get started"
    return 0
  } else {
    Write-Err "Installation failed. Try manually:"
    Write-Err "  python -m pip install siyarix"
    return 1
  }
}

exit (Main)
