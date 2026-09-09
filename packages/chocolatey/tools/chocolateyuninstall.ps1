$ErrorActionPreference = 'Stop'

$packageName = 'siyarix'
$version = '1.0.1'

Write-Host "Uninstalling $packageName $version..."

# Try multiple uninstall methods
$uninstalled = $false

# Try pip
try {
  $result = & pip uninstall siyarix -y 2>&1
  if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Removed via pip"
    $uninstalled = $true
  }
} catch {
  Write-Warn "pip uninstall failed: $_"
}

# Try pipx
if (-not $uninstalled) {
  try {
    $result = & pipx uninstall siyarix 2>&1
    if ($LASTEXITCODE -eq 0) {
      Write-Host "  ✓ Removed via pipx"
      $uninstalled = $true
    }
  } catch {
    # pipx not installed
  }
}

if ($uninstalled) {
  Write-Host "$packageName $version uninstalled successfully."
} else {
  Write-Warn "Could not uninstall via pip or pipx."
  Write-Warn "Try manually: python -m pip uninstall siyarix"
}

# Config directory notice
$configDir = "$env:USERPROFILE\.siyarix"
if (Test-Path $configDir) {
  Write-Host ""
  Write-Host "Configuration directory preserved: $configDir"
  Write-Host "Remove manually: Remove-Item -Recurse -Force '$configDir'"
}
