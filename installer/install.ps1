<#
.SYNOPSIS
    Siyarix Universal Enterprise Installer for Windows.

.DESCRIPTION
    Automated, enterprise-grade installer for Siyarix (AI Cybersecurity Orchestration Agent).
    Supports Windows 10/11, Windows Server 2019/2022/2025, and Windows on ARM64.
    Cascade package managers: uv -> pipx -> pip -> winget -> chocolatey -> scoop.

.PARAMETER Version
    Specific Siyarix version to install (defaults to 1.1.0 or $env:SIYARIX_VERSION).

.PARAMETER Method
    Forced installation method: auto, uv, pipx, pip, winget, choco, scoop.

.PARAMETER Silent
    Unattended / silent execution mode with minimal output.

.PARAMETER DryRun
    Simulate the installation without writing changes or downloading packages.

.PARAMETER WithTools
    Install standard security tool integrations.

.PARAMETER NoModifyPath
    Skip updating User or Session PATH environment variables.

.PARAMETER Help
    Show help and parameter reference.

.EXAMPLE
    irm https://siyarix.github.io/install.ps1 | iex
    irm https://siyarix.github.io/install.ps1 | iex -ArgumentList "-Method uv"
#>

[CmdletBinding()]
param (
    [Alias("v")]
    [string]$Version = $(if ($env:SIYARIX_VERSION) { $env:SIYARIX_VERSION } else { "1.1.0" }),

    [Alias("m")]
    [ValidateSet("auto", "uv", "pipx", "pip", "winget", "choco", "scoop")]
    [string]$Method = $(if ($env:SIYARIX_METHOD) { $env:SIYARIX_METHOD } else { "auto" }),

    [Alias("s", "Quiet", "NonInteractive")]
    [switch]$Silent = $(if ($env:SIYARIX_SILENT -eq "1") { $true } else { $false }),

    [Alias("d")]
    [switch]$DryRun = $(if ($env:SIYARIX_DRY_RUN -eq "1") { $true } else { $false }),

    [switch]$WithTools = $(if ($env:SIYARIX_WITH_TOOLS -eq "1") { $true } else { $false }),

    [switch]$NoModifyPath = $(if ($env:SIYARIX_NO_MODIFY_PATH -eq "1") { $true } else { $false }),

    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$Script:InstalledMethod = ""
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Write-Banner {
    if ($Silent) { return }
    Write-Host @"
   ███████╗██╗██╗   ██╗ █████╗ ██████╗ ██╗██╗  ██╗
   ██╔════╝██╚██╗ ██╔╝██╔══██╗██╔══██╗██║╚██╗██╔╝
   ███████╗██║╚████╔╝ ███████║██████╔╝██║ ╚███╔╝
   ╚════██║██║ ╚██╔╝  ██╔══██║██╔══██╗██║ ██╔██╗
   ███████║██║  ██║   ██║  ██║██║  ██║██║██╔╝ ██╗
   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
   AI Cybersecurity Orchestration Agent v$Version
"@ -ForegroundColor Cyan
    Write-Host "   Windows Enterprise Installer -- " -NoNewline
    Write-Host "https://siyarix.github.io`n" -ForegroundColor DarkCyan
}

function Write-Info  { if (-not $Silent) { Write-Host "==>" -ForegroundColor Blue -NoNewline; Write-Host " $args" } }
function Write-Ok    { if (-not $Silent) { Write-Host "  $([char]0x2713)" -ForegroundColor Green -NoNewline; Write-Host " $args" } }
function Write-Warn  { Write-Host "  !" -ForegroundColor Yellow -NoNewline; Write-Host " $args" }
function Write-Err   { Write-Host "  $([char]0x2717)" -ForegroundColor Red -NoNewline; Write-Host " $args" }

function Show-HelpGuide {
    Write-Host @"
Siyarix Windows Enterprise Installer

USAGE:
  irm https://siyarix.github.io/install.ps1 | iex
  powershell -ExecutionPolicy Bypass -File install.ps1 [OPTIONS]

OPTIONS:
  -Version <string>     Specify version to install (default: 1.1.0)
  -Method <string>      Force installer method: auto, uv, pipx, pip, winget, choco, scoop
  -Silent               Silent mode, suppress non-error outputs
  -DryRun               Simulate installation actions without modifying system
  -WithTools            Install optional cybersecurity auxiliary tools
  -NoModifyPath         Do not append binary directories to User PATH
  -Help                 Display this help screen

ENVIRONMENT VARIABLES:
  SIYARIX_VERSION, SIYARIX_METHOD, SIYARIX_SILENT, SIYARIX_DRY_RUN,
  SIYARIX_WITH_TOOLS, SIYARIX_NO_MODIFY_PATH
"@
}

function Get-Arch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()
    switch ($arch) {
        "x64" { return "x64" }
        "arm64" { return "arm64" }
        "x86" { return "x86" }
        default { return $arch }
    }
}

function Test-AdminRole {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-LongPathSupport {
    try {
        $val = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -ErrorAction SilentlyContinue
        return ($val.LongPathsEnabled -eq 1)
    } catch { return $false }
}

function Enable-LongPathSupport {
    if (-not (Test-LongPathSupport)) {
        if (Test-AdminRole) {
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -Value 1 -ErrorAction SilentlyContinue
                Write-Ok "Enabled Windows LongPathsEnabled in registry"
            } catch {
                Write-Warn "Could not automatically set LongPathsEnabled: $_"
            }
        } else {
            Write-Warn "Windows Long Path support is disabled. If you hit path-length errors, run as Administrator:"
            Write-Warn '  reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f'
        }
    }
}

function Update-PathEnvironment {
    param([string]$PathToAdd)
    if ($NoModifyPath) { return }
    if (-not (Test-Path $PathToAdd)) { return }

    try {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $paths = $userPath -split ';' | Where-Object { $_.Trim() -ne "" }
        if ($paths -notcontains $PathToAdd) {
            if ($DryRun) {
                Write-Info "[DRY-RUN] Would add $PathToAdd to User PATH"
                return
            }
            $newUserPath = ($paths + $PathToAdd) -join ';'
            [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
            Write-Ok "Added $PathToAdd to User PATH"
        }

        # Update current process session
        $sessionPaths = $env:PATH -split ';' | Where-Object { $_.Trim() -ne "" }
        if ($sessionPaths -notcontains $PathToAdd) {
            $env:PATH = ($sessionPaths + $PathToAdd) -join ';'
        }
    } catch {
        Write-Warn "Failed to update PATH environment: $_"
    }
}

function Find-PythonCommand {
    # Check py launcher
    foreach ($v in @("3.13", "3.12", "3.11")) {
        try {
            $testOut = & py -$v --version 2>&1
            if ($testOut -match "Python\s+3\.(11|12|13)") {
                return @("py", "-$v")
            }
        } catch {}
    }

    # Check python / python3
    foreach ($cmd in @("python", "python3")) {
        try {
            $testOut = & $cmd --version 2>&1
            if ($testOut -match "Python\s+3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 11) {
                    return @($cmd)
                }
            }
        } catch {}
    }
    return $null
}

function Install-PythonBootstrap {
    Write-Info "Python 3.11+ not found on system. Bootstrapping Python runtime..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would bootstrap Python 3.12 runtime"
        return $true
    }

    # 1. Try winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Attempting Python installation via winget..."
        try {
            & winget install Python.Python.3.12 --accept-source-agreements --accept-package-agreements --silent --no-upgrade
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Python 3.12 installed via winget"
                return $true
            }
        } catch {}
    }

    # 2. Try chocolatey
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info "Attempting Python installation via Chocolatey..."
        try {
            & choco install python3 --version=3.12.4 -y --no-progress
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Python 3 installed via Chocolatey"
                return $true
            }
        } catch {}
    }

    # 3. Try scoop
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Info "Attempting Python installation via Scoop..."
        try {
            & scoop install python
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Python installed via Scoop"
                return $true
            }
        } catch {}
    }

    # 4. Direct official Python binary installer
    Write-Info "Downloading official Python 3.12 installer..."
    $arch = Get-Arch
    $installerName = if ($arch -eq "arm64") { "python-3.12.9-arm64.exe" } else { "python-3.12.9-amd64.exe" }
    $pythonUrl = "https://www.python.org/ftp/python/3.12.9/$installerName"
    $dest = Join-Path $env:TEMP $installerName

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($pythonUrl, $dest)

        Write-Info "Running silent Python installation..."
        $installArgs = "/quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_doc=0 Include_launcher=1"
        $proc = Start-Process -FilePath $dest -ArgumentList $installArgs -Wait -PassThru
        Remove-Item $dest -Force -ErrorAction SilentlyContinue

        if ($proc.ExitCode -eq 0) {
            Write-Ok "Official Python 3.12 installed successfully"
            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
            return $true
        }
    } catch {
        Write-Warn "Direct Python installer failed: $_"
    }

    return $false
}

function Install-ViaUv {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Info "Installing Siyarix using uv (enterprise high-performance)..."
    $pkg = if ($WithTools) { "siyarix[all]" } else { "siyarix" }
    if ($Version -and $Version -ne "latest") {
        $pkg = "$pkg==$Version"
    }

    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: uv tool install --force $pkg"
        $Script:InstalledMethod = "uv"
        return $true
    }

    try {
        & uv tool install --force $pkg 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "uv"
            $uvBin = Join-Path $env:USERPROFILE ".cargo\bin"
            Update-PathEnvironment -PathToAdd $uvBin
            return $true
        }
    } catch {}
    return $false
}

function Install-ViaPipx {
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Info "Installing Siyarix using pipx (isolated environment)..."
    $pkg = if ($WithTools) { "siyarix[all]" } else { "siyarix" }
    if ($Version -and $Version -ne "latest") {
        $pkg = "$pkg==$Version"
    }

    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: pipx install --force $pkg"
        $Script:InstalledMethod = "pipx"
        return $true
    }

    try {
        & pipx install --force $pkg 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "pipx"
            $pipxBin = Join-Path $env:USERPROFILE ".local\bin"
            Update-PathEnvironment -PathToAdd $pipxBin
            return $true
        }
    } catch {}
    return $false
}

function Install-ViaPip {
    param([string[]]$PyCmd)
    if (-not $PyCmd) { return $false }

    Write-Info "Installing Siyarix using pip..."
    $pkg = if ($WithTools) { "siyarix[all]" } else { "siyarix" }
    if ($Version -and $Version -ne "latest") {
        $pkg = "$pkg==$Version"
    }

    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: $($PyCmd -join ' ') -m pip install --upgrade $pkg"
        $Script:InstalledMethod = "pip"
        return $true
    }

    try {
        # Upgrade pip quietly
        & $PyCmd -m pip install --upgrade pip --no-input --quiet 2>&1 | Out-Null

        if ($env:VIRTUAL_ENV) {
            & $PyCmd -m pip install --upgrade $pkg --no-input 2>&1 | Out-Null
        } else {
            & $PyCmd -m pip install --upgrade --user $pkg --no-input 2>&1 | Out-Null
        }

        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "pip"
            # Locate user base scripts
            try {
                $userBase = & $PyCmd -c "import site; print(site.USER_BASE)" 2>$null
                if ($userBase -and (Test-Path "$userBase\Scripts")) {
                    Update-PathEnvironment -PathToAdd "$userBase\Scripts"
                }
            } catch {}
            return $true
        }
    } catch {}
    return $false
}

function Install-ViaWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Info "Installing Siyarix using winget..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: winget install Mufthakherul.Siyarix --accept-package-agreements --silent"
        $Script:InstalledMethod = "winget"
        return $true
    }

    try {
        & winget install Mufthakherul.Siyarix --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "winget"
            return $true
        }
    } catch {}
    return $false
}

function Install-ViaChoco {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Info "Installing Siyarix using Chocolatey..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: choco install siyarix -y --no-progress"
        $Script:InstalledMethod = "choco"
        return $true
    }

    try {
        & choco install siyarix -y --no-progress 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "choco"
            return $true
        }
    } catch {}
    return $false
}

function Install-ViaScoop {
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Info "Installing Siyarix using Scoop..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: scoop install extras; scoop install siyarix"
        $Script:InstalledMethod = "scoop"
        return $true
    }

    try {
        & scoop bucket add extras 2>$null | Out-Null
        & scoop install siyarix 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $Script:InstalledMethod = "scoop"
            return $true
        }
    } catch {}
    return $false
}

function Rollback-Installation {
    if ($DryRun) { return }
    Write-Warn "Installation failed. Cleaning up partial changes..."
    switch ($Script:InstalledMethod) {
        "uv" { & uv tool uninstall siyarix 2>$null | Out-Null }
        "pipx" { & pipx uninstall siyarix 2>$null | Out-Null }
        "pip" {
            $py = Find-PythonCommand
            if ($py) { & $py -m pip uninstall -y siyarix 2>$null | Out-Null }
        }
        "choco" { & choco uninstall siyarix -y 2>$null | Out-Null }
        "scoop" { & scoop uninstall siyarix 2>$null | Out-Null }
    }
}

# --- Main Entry Point ---
if ($Help) {
    Show-HelpGuide
    exit 0
}

Write-Banner

$arch = Get-Arch
Write-Info "Detected Windows Architecture: $arch"
Write-Info "PowerShell Version: $($PSVersionTable.PSVersion.ToString())"

Enable-LongPathSupport

# Check if already installed
if (-not $DryRun -and $Method -eq "auto") {
    try {
        $existing = & siyarix --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $existing -match "siyarix") {
            Write-Ok "Siyarix is already installed: $existing"
            Write-Info "To reinstall or upgrade, run with -Method uv (or pipx, pip) or pass an updated -Version."
            exit 0
        }
    } catch {}
}

# Ensure Python / uv is available
$pyCmd = Find-PythonCommand
$hasUv = [bool](Get-Command uv -ErrorAction SilentlyContinue)

if (-not $pyCmd -and -not $hasUv) {
    $bootstrapOk = Install-PythonBootstrap
    if ($bootstrapOk) {
        $pyCmd = Find-PythonCommand
    }
}

if (-not $pyCmd -and -not $hasUv -and $Method -ne "winget" -and $Method -ne "choco" -and $Method -ne "scoop") {
    Write-Err "Python 3.11+ is required but could not be installed automatically."
    Write-Err "Please install Python 3.11+ manually from https://www.python.org/downloads/ and re-run this script."
    exit 1
}

$success = $false

if ($Method -ne "auto") {
    Write-Info "Targeting user-specified install method: $Method"
    switch ($Method) {
        "uv"     { $success = Install-ViaUv }
        "pipx"   { $success = Install-ViaPipx }
        "pip"    { $success = Install-ViaPip -PyCmd $pyCmd }
        "winget" { $success = Install-ViaWinget }
        "choco"  { $success = Install-ViaChoco }
        "scoop"  { $success = Install-ViaScoop }
    }
} else {
    # Automatic cascading sequence: uv -> pipx -> pip -> winget -> choco -> scoop
    $methods = @(
        { Install-ViaUv },
        { Install-ViaPipx },
        { Install-ViaPip -PyCmd $pyCmd },
        { Install-ViaWinget },
        { Install-ViaChoco },
        { Install-ViaScoop }
    )

    foreach ($step in $methods) {
        try {
            if (& $step) {
                $success = $true
                break
            }
        } catch {
            Write-Warn "Method attempt failed: $_"
        }
    }
}

if (-not $success) {
    Rollback-Installation
    Write-Err "Failed to install Siyarix v$Version using available package managers."
    Write-Err "Manual fallback: python -m pip install --upgrade siyarix"
    Write-Err "Issue tracker: https://github.com/mufthakherul/siyarix/issues"
    exit 1
}

# Verification check
if (-not $DryRun) {
    $verifySiyarix = Get-Command siyarix -ErrorAction SilentlyContinue
    if (-not $verifySiyarix) {
        Write-Warn "'siyarix' command is not immediately found in current session PATH."
        Write-Warn "Please restart your PowerShell terminal or execute:"
        Write-Warn '  $env:PATH = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")'
    } else {
        Write-Ok "Verified executable: $($verifySiyarix.Source)"
    }
}

if (-not $Silent) {
    Write-Host ""
    Write-Ok "Siyarix v$Version installed successfully via $Script:InstalledMethod!"
    Write-Host @"

Quick Start:
  siyarix --help                  # View command-line interface options
  siyarix init                    # Setup workspace and interactive configuration
  siyarix audit                   # Run comprehensive system security audit
  siyarix chat                    # Launch interactive AI orchestration terminal

Documentation: https://siyarix.github.io/docs
Uninstaller:   irm https://siyarix.github.io/uninstall.ps1 | iex
"@ -ForegroundColor Cyan
}

exit 0
