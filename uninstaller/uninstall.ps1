<#
.SYNOPSIS
    Siyarix Windows Enterprise Uninstaller.

.DESCRIPTION
    Automated uninstallation tool for Siyarix (AI Cybersecurity Orchestration Agent).
    Supports Standard Uninstallation (removes binaries/packages, keeps data) and
    Deep Dive (forensic-grade trace purge of configs, logs, models, keyring, history).

.PARAMETER Mode
    Uninstall mode: 'Regular' (default) or 'Deep'.

.PARAMETER Regular
    Perform regular package uninstallation without interactive prompts.

.PARAMETER Deep
    Perform forensic trace purge without interactive prompts.

.PARAMETER Purge
    Alias for -Deep.

.PARAMETER Yes
    Automatically confirm all prompts.

.PARAMETER Silent
    Suppress interactive prompts and non-error messages.

.PARAMETER DryRun
    Simulate uninstallation actions without modifying the system.

.PARAMETER Help
    Show this help documentation.

.EXAMPLE
    irm https://siyarix.github.io/uninstall.ps1 | iex
    irm https://siyarix.github.io/uninstall.ps1 | iex -ArgumentList "-Deep -Yes"
#>

[CmdletBinding()]
param (
    [ValidateSet("Regular", "Deep")]
    [string]$Mode = $(if ($env:SIYARIX_UNINSTALL_MODE) { $env:SIYARIX_UNINSTALL_MODE } else { "" }),

    [switch]$Regular,

    [Alias("p")]
    [switch]$Deep,

    [switch]$Purge,

    [Alias("y", "Force")]
    [switch]$Yes = $(if ($env:SIYARIX_YES -eq "1") { $true } else { $false }),

    [Alias("s", "Quiet")]
    [switch]$Silent = $(if ($env:SIYARIX_SILENT -eq "1") { $true } else { $false }),

    [Alias("d")]
    [switch]$DryRun = $(if ($env:SIYARIX_DRY_RUN -eq "1") { $true } else { $false }),

    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$SIYARIX_VERSION = "1.1.0"
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
   AI Cybersecurity Orchestration Agent Windows Uninstaller v$SIYARIX_VERSION
"@ -ForegroundColor Cyan
    Write-Host "   Enterprise Uninstaller -- " -NoNewline
    Write-Host "https://siyarix.github.io`n" -ForegroundColor DarkCyan
}

function Write-Info  { if (-not $Silent) { Write-Host "==>" -ForegroundColor Blue -NoNewline; Write-Host " $args" } }
function Write-Ok    { if (-not $Silent) { Write-Host "  $([char]0x2713)" -ForegroundColor Green -NoNewline; Write-Host " $args" } }
function Write-Warn  { Write-Host "  !" -ForegroundColor Yellow -NoNewline; Write-Host " $args" }
function Write-Err   { Write-Host "  $([char]0x2717)" -ForegroundColor Red -NoNewline; Write-Host " $args" }

function Show-HelpGuide {
    Write-Host @"
Siyarix Windows Enterprise Uninstaller

USAGE:
  irm https://siyarix.github.io/uninstall.ps1 | iex
  powershell -ExecutionPolicy Bypass -File uninstall.ps1 [OPTIONS]

OPTIONS:
  -Regular              Perform standard package removal (preserves data and config)
  -Deep, -Purge         Forensic purge: removes packages, ~/.siyarix, keyring, history
  -Yes, -y              Auto-confirm all confirmation prompts
  -Silent               Silent mode, suppress standard console output
  -DryRun               Simulate uninstallation actions without changing system
  -Help                 Display this help reference
"@
}

function Test-AdminRole {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Remove-PathEntry {
    param([string]$TargetSubstring)
    try {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $paths = $userPath -split ';' | Where-Object { $_.Trim() -ne "" -and $_ -notlike "*$TargetSubstring*" }
        $newUserPath = $paths -join ';'
        if ($userPath -ne $newUserPath) {
            if (-not $DryRun) {
                [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
            }
            Write-Ok "Removed '$TargetSubstring' entry from User PATH."
        }

        if (Test-AdminRole) {
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $mPaths = $machinePath -split ';' | Where-Object { $_.Trim() -ne "" -and $_ -notlike "*$TargetSubstring*" }
            $newMachinePath = $mPaths -join ';'
            if ($machinePath -ne $newMachinePath) {
                if (-not $DryRun) {
                    [Environment]::SetEnvironmentVariable("Path", $newMachinePath, "Machine")
                }
                Write-Ok "Removed '$TargetSubstring' entry from Machine PATH."
            }
        }
    } catch {
        Write-Warn "Failed to update PATH environment: $_"
    }
}

if ($Help) {
    Show-HelpGuide
    exit 0
}

Write-Banner

$isAdmin = Test-AdminRole
if (-not $isAdmin -and -not $Silent) {
    Write-Warn "Not running as Administrator. Forensic Prefetch and system logs cleanup require elevation."
}

# --- Detection ---
$uvDetected = $false
$pipxDetected = $false
$pipDetected = $false
$wingetDetected = $false
$chocoDetected = $false
$scoopDetected = $false
$cloneDetected = $false

# 1. uv tool
if (Get-Command uv -ErrorAction SilentlyContinue) {
    try {
        $uvList = & uv tool list 2>$null
        if ($uvList -and ($uvList | Select-String "siyarix")) {
            $uvDetected = $true
        }
    } catch {}
}

# 2. pipx
if (Get-Command pipx -ErrorAction SilentlyContinue) {
    try {
        $pipxList = & pipx list 2>$null
        if ($pipxList -and ($pipxList | Select-String "siyarix")) {
            $pipxDetected = $true
        }
    } catch {}
}

# 3. pip
try {
    $pipShow = & python -m pip show siyarix 2>$null
    if ($pipShow) {
        $pipDetected = $true
    }
} catch {}

# 4. winget
if (Get-Command winget -ErrorAction SilentlyContinue) {
    try {
        $wingetList = & winget list Mufthakherul.Siyarix 2>$null
        if ($LASTEXITCODE -eq 0 -and $wingetList -and ($wingetList | Select-String "siyarix")) {
            $wingetDetected = $true
        }
    } catch {}
}

# 5. choco
if (Get-Command choco -ErrorAction SilentlyContinue) {
    try {
        $chocoList = & choco list -lo siyarix 2>$null
        if ($chocoList -and ($chocoList | Select-String "siyarix")) {
            $chocoDetected = $true
        }
    } catch {}
}

# 6. scoop
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    try {
        $scoopList = & scoop list siyarix 2>$null
        if ($LASTEXITCODE -eq 0 -and $scoopList -and ($scoopList | Select-String "siyarix")) {
            $scoopDetected = $true
        }
    } catch {}
}

# 7. clone
if ((Test-Path "pyproject.toml") -and (Test-Path ".git")) {
    $tomlContent = Get-Content "pyproject.toml" -ErrorAction SilentlyContinue
    if ($tomlContent -and ($tomlContent | Select-String 'name = "siyarix"')) {
        $cloneDetected = $true
    }
}

if (-not ($uvDetected -or $pipxDetected -or $pipDetected -or $wingetDetected -or $chocoDetected -or $scoopDetected -or $cloneDetected)) {
    Write-Warn "No active installations of Siyarix were auto-detected on this system."
    Write-Warn "You may still run Deep Purge to clean configuration files or execution traces."
} else {
    Write-Info "Detected Siyarix installations:"
    if ($uvDetected) { Write-Ok "  - Installed via uv tool" }
    if ($pipxDetected) { Write-Ok "  - Installed via pipx" }
    if ($pipDetected) { Write-Ok "  - Installed via pip" }
    if ($wingetDetected) { Write-Ok "  - Installed via winget" }
    if ($chocoDetected) { Write-Ok "  - Installed via Chocolatey" }
    if ($scoopDetected) { Write-Ok "  - Installed via Scoop" }
    if ($cloneDetected) { Write-Ok "  - Local Git clone directory" }
}

# Determine Mode
$chosenMode = "Regular"
if ($Deep -or $Purge -or $Mode -eq "Deep") {
    $chosenMode = "Deep"
} elseif ($Regular -or $Mode -eq "Regular" -or $Yes) {
    $chosenMode = "Regular"
} else {
    Write-Host "`nSelect uninstallation method:"
    Write-Host "  1) Standard   [Remove binary/package, preserve ~/.siyarix config and memory]"
    Write-Host "  2) Deep Purge [Forensic cleanup: Purge configs, models, memory DB, keyring, history]"
    $choice = Read-Host "Select option (1 or 2)"
    if ($choice -eq "2") {
        $chosenMode = "Deep"
    } else {
        $chosenMode = "Regular"
    }
}

# Execute package removal
Write-Info "Executing Package Removal..."
$uninstalled = $false

if ($uvDetected) {
    Write-Info "Removing from uv tool..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: uv tool uninstall siyarix"
        $uninstalled = $true
    } else {
        try {
            & uv tool uninstall siyarix 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "uv uninstall notice: $_" }
    }
}

if ($pipxDetected) {
    Write-Info "Removing from pipx..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: pipx uninstall siyarix"
        $uninstalled = $true
    } else {
        try {
            & pipx uninstall siyarix 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "pipx uninstall notice: $_" }
    }
}

if ($pipDetected) {
    Write-Info "Removing from pip..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: python -m pip uninstall siyarix -y"
        $uninstalled = $true
    } else {
        try {
            & python -m pip uninstall siyarix -y 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "pip uninstall notice: $_" }
    }
}

if ($wingetDetected) {
    Write-Info "Removing from winget..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: winget uninstall Mufthakherul.Siyarix --silent"
        $uninstalled = $true
    } else {
        try {
            & winget uninstall Mufthakherul.Siyarix --silent 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "winget uninstall notice: $_" }
    }
}

if ($chocoDetected) {
    Write-Info "Removing from Chocolatey..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: choco uninstall siyarix -y"
        $uninstalled = $true
    } else {
        try {
            & choco uninstall siyarix -y 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "choco uninstall notice: $_" }
    }
}

if ($scoopDetected) {
    Write-Info "Removing from Scoop..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: scoop uninstall siyarix"
        $uninstalled = $true
    } else {
        try {
            & scoop uninstall siyarix 2>&1 | Out-Null
            $uninstalled = $true
        } catch { Write-Warn "scoop uninstall notice: $_" }
    }
}

if ($cloneDetected) {
    Write-Info "Cleaning build caches in local clone..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would clean build caches in repository"
    } else {
        $dirs = @(".venv", "venv", "dist", "build", "*.egg-info", ".pytest_cache", ".mypy_cache", ".ruff_cache")
        foreach ($d in $dirs) {
            if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
        Get-ChildItem -Filter "__pycache__" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Cleaned local clone build files."
    }
}

if ($uninstalled) {
    Write-Ok "Siyarix binary/package removal completed."
}

# Deep Purge execution
if ($chosenMode -eq "Deep") {
    Write-Info "Initiating Deep Dive (Forensic trace purge)..."

    # 1. Config & Data directories
    $userHome = [System.Environment]::GetFolderPath("UserProfile")
    $siyarixDirs = @(
        "$userHome\.siyarix",
        "$env:APPDATA\siyarix",
        "$env:LOCALAPPDATA\siyarix"
    )

    $customConfig = $env:SIYARIX_CONFIG_DIR
    if (-not $customConfig) { $customConfig = $env:SIYARIX_HOME }
    if (-not $customConfig) { $customConfig = $env:SIYARIX_CONFIG }
    if ($customConfig) { $siyarixDirs += $customConfig }

    foreach ($dir in $siyarixDirs) {
        if (Test-Path $dir) {
            Write-Info "Deleting config/data directory: $dir"
            if ($DryRun) {
                Write-Info "[DRY-RUN] Would remove: $dir"
            } else {
                try {
                    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Ok "Purged: $dir"
                } catch {
                    Write-Warn "Could not remove directory: $dir"
                }
            }
        }
    }

    # 2. Keyring credentials
    Write-Info "Purging stored OS keyring credentials..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would delete password 'cred_store_key' from keyring"
    } else {
        try {
            & python -c "import keyring; keyring.delete_password('siyarix', 'cred_store_key')" 2>$null
            Write-Ok "Purged OS keyring entries."
        } catch {}
    }

    # 3. PATH cleanup
    Write-Info "Removing Siyarix references from PATH environment variables..."
    Remove-PathEntry -TargetSubstring ".siyarix"

    # 4. PowerShell command history purge
    try {
        $historyPath = (Get-PSReadLineOption).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath)) {
            Write-Info "Purging Siyarix commands from PowerShell history..."
            if ($DryRun) {
                Write-Info "[DRY-RUN] Would filter out 'siyarix' from $historyPath"
            } else {
                $historyContent = Get-Content $historyPath -ErrorAction SilentlyContinue
                if ($historyContent) {
                    $cleaned = $historyContent | Where-Object { $_ -notmatch 'siyarix' }
                    Set-Content $historyPath $cleaned -Force
                    Write-Ok "Purged PowerShell history entries."
                }
            }
        }
    } catch {
        Write-Warn "Could not inspect PowerShell history: $_"
    }

    # 5. Prefetch Traces (Forensic cleanup)
    if ($isAdmin) {
        Write-Info "Purging Windows Prefetch traces..."
        try {
            $pfFiles = Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "*siyarix*.pf" -ErrorAction SilentlyContinue
            foreach ($pf in $pfFiles) {
                Write-Info "Deleting prefetch: $($pf.Name)"
                if (-not $DryRun) {
                    Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Ok "Prefetch traces removed."
        } catch {
            Write-Warn "Prefetch cleanup notice: $_"
        }
    }

    # 6. MUICache registry entries
    Write-Info "Cleaning MUICache registry traces..."
    $muiPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiPath) {
        try {
            $muiKey = Get-Item $muiPath
            foreach ($valName in $muiKey.GetValueNames()) {
                if ($valName -like "*siyarix*" -or ($muiKey.GetValue($valName) -like "*siyarix*")) {
                    Write-Info "Removing MUICache entry: $valName"
                    if (-not $DryRun) {
                        Remove-ItemProperty -Path $muiPath -Name $valName -ErrorAction SilentlyContinue
                    }
                }
            }
            Write-Ok "MUICache registry entries cleaned."
        } catch {
            Write-Warn "MUICache notice: $_"
        }
    }

    # 7. Recent Items
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Write-Info "Cleaning Windows Recent Items..."
        try {
            $recentFiles = Get-ChildItem -Path $recentPath -Filter "*siyarix*" -ErrorAction SilentlyContinue
            foreach ($rf in $recentFiles) {
                if (-not $DryRun) {
                    Remove-Item $rf.FullName -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Ok "Recent shortcuts cleaned."
        } catch {}
    }

    # 8. Temporary files
    Write-Info "Purging temporary files..."
    $tempDirs = @($env:TEMP, "$env:SystemRoot\Temp")
    foreach ($td in $tempDirs) {
        if (Test-Path $td) {
            try {
                $tFiles = Get-ChildItem -Path $td -Filter "*siyarix*" -Recurse -ErrorAction SilentlyContinue
                foreach ($tf in $tFiles) {
                    if (-not $DryRun) {
                        Remove-Item $tf.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {}
        }
    }
    Write-Ok "Temporary files cleaned."

    # 9. Package manager caches
    try {
        if (Get-Command uv -ErrorAction SilentlyContinue -and -not $DryRun) {
            & uv cache clean siyarix 2>$null | Out-Null
        }
        if (-not $DryRun) {
            & python -m pip cache remove siyarix 2>$null | Out-Null
        }
    } catch {}

    Write-Ok "Deep dive uninstallation complete. All forensic traces removed."
}

if (-not $Silent) {
    Write-Host "`nSiyarix uninstallation finished.`n" -ForegroundColor Green
}

exit 0
