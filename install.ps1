#!/usr/bin/env pwsh
# =============================================================================
# Siyarix Universal Installer for Windows
#   One-liner: irm https://siyarix.dev/install.ps1 | iex
#
# Supports: Windows 10/11, Windows Server 2019/2022/2025, Windows Server Core
# Package managers: pipx, pip, winget, chocolatey, scoop
# =============================================================================

$ErrorActionPreference = 'Stop'
$__script_version = "3.0.0"

function Write-Banner {
  @"
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v$__script_version
"@
  Write-Host "`nSiyarix — AI Cybersecurity Orchestration Agent`n" -ForegroundColor Cyan
}

function Write-Info  { Write-Host "==>" -ForegroundColor Blue -NoNewline; Write-Host " $args" }
function Write-Ok    { Write-Host "  ✓" -ForegroundColor Green -NoNewline; Write-Host " $args" }
function Write-Warn  { Write-Host "  !" -ForegroundColor Yellow -NoNewline; Write-Host " $args" }
function Write-Err   { Write-Host "  ✗" -ForegroundColor Red -NoNewline; Write-Host " $args" }

function Get-PowerShellVersion {
  $psVer = $PSVersionTable.PSVersion
  return "$($psVer.Major).$($psVer.Minor)"
}

function Test-LongPathSupport {
  try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $val = Get-ItemProperty -Path $regPath -Name "LongPathsEnabled" -ErrorAction SilentlyContinue
    return ($val.LongPathsEnabled -eq 1)
  } catch {
    return $false
  }
}

function Enable-LongPathSupport {
  if (-not (Test-LongPathSupport)) {
    Write-Warn "Windows long path support is not enabled."
    Write-Warn "To enable: Open gpedit.msc → Computer Config → Admin Templates → System → Filesystem → Enable Win32 long paths"
    Write-Warn "Or run as Administrator:"
    Write-Warn '  reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f'
    Write-Warn ""
  }
}

function Update-Path {
  param([string]$PathToAdd)
  try {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$PathToAdd*") {
      [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$PathToAdd", "User")
      Write-Ok "Added $PathToAdd to PATH"
      # Update current session PATH
      $env:PATH = "$env:PATH;$PathToAdd"
    }
  } catch {
    Write-Warn "Failed to update PATH: $_"
  }
}

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

function Install-ViaScoop {
  Write-Info "Installing via Scoop..."
  try {
    scoop bucket add extras 2>$null
    scoop install siyarix
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

# --- Admin / Elevated Check ---
function Test-Admin {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

# --- Execution Policy Check ---
function Test-ExecutionPolicy {
  $policy = Get-ExecutionPolicy -Scope CurrentUser
  if ($policy -eq "Restricted" -or $policy -eq "AllSigned") {
    Write-Warn "Current execution policy: $policy"
    Write-Warn "To run scripts, set: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned"
    return $false
  }
  return $true
}

# --- Main ---
function Main {
  Write-Banner

  # PowerShell version check
  $psVer = Get-PowerShellVersion
  Write-Info "PowerShell version: $psVer"

  # Execution policy check
  Test-ExecutionPolicy | Out-Null

  # Long path support check
  Enable-LongPathSupport

  # Admin check (elevation not required for user-install but warn if winget/choco will be used)
  $isAdmin = Test-Admin
  if (-not $isAdmin) {
    Write-Warn "Not running as Administrator."
    Write-Warn "Winget, Chocolatey, and Scoop installers may require elevation."
    Write-Warn "Re-run from an elevated PowerShell if those methods fail.`n"
  }

  # Parse arguments
  $version = $__script_version
  $dryRun = $false
  for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
      '--version' { $version = $args[++$i] }
      '--dry-run' { $dryRun = $true }
      '--help' {
        Write-Host "Usage: irm https://siyarix.dev/install.ps1 | iex"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  --version VERSION    Version to install"
        Write-Host "  --dry-run            Simulate installation"
        Write-Host "  --help               Show this help"
        return 0
      }
    }
  }

  if ($dryRun) {
    Write-Info "Dry-run mode enabled"
    Write-Info "Would install Siyarix v$version"
    return 0
  }

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

  # Check for pip
  try {
    $pipVer = pip --version 2>&1
    Write-Ok "pip found: $($pipVer -split ' ' | Select-Object -First 2 -Join ' ')"
  } catch {
    Write-Warn "pip not found. The pip installer will attempt to bootstrap it."
  }

  # Try installers in order of preference (pipx/win-wrap aware)
  $installers = @(
    { Install-ViaPipx }.GetNewClosure(),
    { Install-ViaPip }.GetNewClosure(),
    { Install-ViaWinget }.GetNewClosure(),
    { Install-ViaChoco }.GetNewClosure(),
    { Install-ViaScoop }.GetNewClosure()
  )

  $installed = $false
  $lastError = ""
  foreach ($installer in $installers) {
    try {
      $result = & $installer
      if ($result) { $installed = $true; break }
    } catch {
      $lastError = $_.Exception.Message
      continue
    }
  }

  # Update PATH for pip install --user locations
  $pythonUserBase = python -c "import site; print(site.USER_BASE)" 2>$null
  if ($pythonUserBase) {
    Update-Path -PathToAdd "$pythonUserBase\Scripts"
  }

  if ($installed) {
    Write-Ok "Siyarix v$__script_version installed successfully!"
    Write-Info "Run 'siyarix --help' to get started"
    return 0
  } else {
    Write-Err "Installation failed: $lastError"
    Write-Err ""
    Write-Err "Try manually:"
    Write-Err "  python -m pip install siyarix"
    Write-Err "  or pipx install siyarix"
    return 1
  }
}

exit (Main)
