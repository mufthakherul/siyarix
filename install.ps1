#!/usr/bin/env pwsh
# =============================================================================
# Siyarix Universal Installer for Windows
#   One-liner: irm https://siyarix.github.io/install.ps1 | iex
#
# Supports: Windows 10/11, Windows Server 2019/2022/2025
# Package managers: pipx, pip, winget, chocolatey, scoop
#
# Note: cryptography ships pre-built wheels for Windows x64, so Rust is NOT
# required. If pip is missing, it will be bootstrapped via ensurepip.
# =============================================================================

$ErrorActionPreference = 'Stop'
$__script_version = "1.0.1"

function Write-Banner {
  Write-Host @"
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v$__script_version
"@ -ForegroundColor Cyan
  Write-Host "`nSiyarix -- AI Cybersecurity Orchestration Agent`n" -ForegroundColor Cyan
}

function Write-Info  { Write-Host "==>" -ForegroundColor Blue -NoNewline; Write-Host " $args" }
function Write-Ok    { Write-Host "  $([char]0x2713)" -ForegroundColor Green -NoNewline; Write-Host " $args" }
function Write-Warn  { Write-Host "  !" -ForegroundColor Yellow -NoNewline; Write-Host " $args" }
function Write-Err   { Write-Host "  $([char]0x2717)" -ForegroundColor Red -NoNewline; Write-Host " $args" }

function Get-PowerShellVersion {
  $psVer = $PSVersionTable.PSVersion
  return "$($psVer.Major).$($psVer.Minor)"
}

function Test-LongPathSupport {
  try {
    $val = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -ErrorAction SilentlyContinue
    return ($val.LongPathsEnabled -eq 1)
  } catch { return $false }
}

function Enable-LongPathSupport {
  if (-not (Test-LongPathSupport)) {
    Write-Warn "Windows long path support is not enabled."
    Write-Warn "To enable, run as Administrator:"
    Write-Warn '  reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f'
  }
}

function Update-Path {
  param([string]$PathToAdd)
  try {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$PathToAdd*") {
      [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$PathToAdd", "User")
      Write-Ok "Added $PathToAdd to PATH"
      $env:PATH = "$env:PATH;$PathToAdd"
    }
  } catch { Write-Warn "Failed to update PATH: $_" }
}

function Test-Python {
  try {
    $ver = python --version 2>&1
    if ($ver -match "(\d+)\.(\d+)") {
      return ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 11)
    }
  } catch {}
  try {
    $ver = python3 --version 2>&1
    if ($ver -match "(\d+)\.(\d+)") {
      return ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 11)
    }
  } catch {}
  return $false
}

function Ensure-Pip {
  try {
    $null = pip --version 2>&1
    return $true
  } catch {}
  Write-Info "pip not found. Bootstrapping pip..."
  try {
    $null = python -m ensurepip --upgrade 2>&1
    Write-Ok "pip installed via ensurepip"
    return $true
  } catch {
    Write-Warn "ensurepip failed. Attempting get-pip.py..."
    try {
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("https://bootstrap.pypa.io/get-pip.py", "$env:TEMP\get-pip.py")
      python "$env:TEMP\get-pip.py" 2>&1 | Out-Null
      Remove-Item "$env:TEMP\get-pip.py" -Force -ErrorAction SilentlyContinue
      Write-Ok "pip installed via get-pip.py"
      return $true
    } catch {
      Write-Err "Failed to install pip. Install manually: https://pip.pypa.io/en/stable/installation/"
      return $false
    }
  }
}

function Install-ViaPip {
  Write-Info "Installing via pip..."
  if (-not (Ensure-Pip)) { return $false }

  # Upgrade pip first
  python -m pip install --upgrade pip --no-input 2>&1 | Out-Null

  # Try regular install first
  try {
    python -m pip install siyarix --no-input 2>&1 | Out-Null
    return $true
  } catch {}
  # Fall back to --user
  try {
    python -m pip install --user siyarix --no-input 2>&1 | Out-Null
    return $true
  } catch {}
  return $false
}

function Install-ViaPipx {
  Write-Info "Installing via pipx..."
  try {
    pipx install siyarix 2>&1 | Out-Null
    return $true
  } catch { return $false }
}

function Install-ViaWinget {
  Write-Info "Installing via winget..."
  try {
    winget install Mufthakherul.Siyarix --accept-package-agreements --silent 2>&1 | Out-Null
    return $true
  } catch { return $false }
}

function Install-ViaChoco {
  Write-Info "Installing via Chocolatey..."
  try {
    choco install siyarix -y 2>&1 | Out-Null
    return $true
  } catch { return $false }
}

function Install-ViaScoop {
  Write-Info "Installing via Scoop..."
  try {
    scoop bucket add extras 2>$null
    scoop install siyarix 2>&1 | Out-Null
    return $true
  } catch { return $false }
}

function Test-Admin {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Test-ExecutionPolicy {
  $policy = Get-ExecutionPolicy -Scope CurrentUser
  if ($policy -eq "Restricted" -or $policy -eq "AllSigned") {
    Write-Warn "Current execution policy: $policy"
    Write-Warn "To run scripts, set: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned"
    return $false
  }
  return $true
}

function Main {
  Write-Banner

  $psVer = Get-PowerShellVersion
  Write-Info "PowerShell version: $psVer"
  Test-ExecutionPolicy | Out-Null
  Enable-LongPathSupport

  $isAdmin = Test-Admin
  if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Winget/Chocolatey/Scoop may require elevation."
  }

  $version = $__script_version
  $dryRun = $false
  for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
      '--version' { $version = $args[++$i] }
      '--dry-run' { $dryRun = $true }
      '--help' {
        Write-Host "Usage: irm https://siyarix.github.io/install.ps1 | iex"
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
    Write-Info "Dry-run mode enabled. Would install Siyarix v$version"
    return 0
  }

  try {
    $ver = & siyarix --version 2>&1
    Write-Ok "Siyarix already installed: $ver"
    return 0
  } catch {}

  if (-not (Test-Python)) {
    Write-Err "Python 3.11+ is required."
    Write-Err "Download from: https://www.python.org/downloads/"
    Write-Info "After installing Python, re-run this installer."
    return 1
  }
  Write-Ok "Python found: $(python --version 2>&1)"

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
      if (& $installer) { $installed = $true; break }
    } catch { $lastError = $_.Exception.Message }
  }

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
    Write-Err "Try manually: python -m pip install siyarix"
    return 1
  }
}
try {
  $exitCode = Main
} catch {
  Write-Host "`n[!] An unexpected error occurred:" -ForegroundColor Red
  Write-Host $_ -ForegroundColor Red
  $exitCode = 1
}

if ([Environment]::UserInteractive -and -not $env:CI) {
  try {
    Write-Host "`nPress any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
  } catch {}
}

if ($exitCode -ne 0) {
  throw "Installation failed with exit code $exitCode"
}
