$ErrorActionPreference = 'Stop'

$packageName = 'siyarix'
$version = '1.0.1'

Write-Host "Installing $packageName $version..."

# Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
  throw "Python 3.11+ is required. Install from https://www.python.org/downloads/"
}

# Check Python version
$ver = python --version 2>&1
if ($ver -match "(\d+)\.(\d+)") {
  $maj = [int]$Matches[1]
  $min = [int]$Matches[2]
  if ($maj -lt 3 -or ($maj -eq 3 -and $min -lt 11)) {
    throw "Python 3.11+ required, found $maj.$min"
  }
}

# Upgrade pip first
Write-Host "Ensuring pip is up-to-date..."
$pipUpgrade = Start-Process -Wait -PassThru -FilePath "python" -ArgumentList "-m pip install --upgrade pip" -NoNewWindow
if ($pipUpgrade.ExitCode -ne 0) {
  Write-Warn "pip upgrade skipped (non-fatal)"
}

# Install via pip
Write-Host "Installing siyarix via pip..."
try {
  $pipResult = Start-Process -Wait -PassThru -FilePath "python" -ArgumentList "-m pip install siyarix" -NoNewWindow
  if ($pipResult.ExitCode -ne 0) {
    Write-Warn "System-wide install failed; trying --user..."
    $pipResult = Start-Process -Wait -PassThru -FilePath "python" -ArgumentList "-m pip install --user siyarix" -NoNewWindow
    if ($pipResult.ExitCode -ne 0) {
      throw "pip install failed with exit code $($pipResult.ExitCode)"
    }
  }
} catch {
  throw "Failed to install siyarix via pip: $_"
}

# Create config directory
$configDir = "$env:USERPROFILE\.siyarix"
if (-not (Test-Path $configDir)) {
  New-Item -ItemType Directory -Path $configDir -Force | Out-Null
  Write-Host "Created config directory: $configDir"
}

# Verify installation
try {
  $check = & siyarix --version 2>&1
  Write-Host "$packageName $version installed successfully!"
  Write-Host "Verified: $check"
} catch {
  Write-Warn "$packageName installed but verification failed. Ensure Python Scripts directory is in your PATH."
}

Write-Host ""
Write-Host "Run 'siyarix --help' to get started."
