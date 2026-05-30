$ErrorActionPreference = 'Stop'

$packageName = 'siyarix'
$version = '1.0.0'
$url = 'https://github.com/mufthakherul/siyarix/archive/refs/tags/v1.0.0.tar.gz'

Write-Host "Installing $packageName $version..."

# Check Python
$python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) {
  throw "Python 3.11+ is required. Install from https://www.python.org/downloads/"
}

# Install via pip
Write-Host "Installing siyarix via pip..."
$pipResult = Start-Process -Wait -PassThru -FilePath "python" -ArgumentList "-m pip install siyarix" -NoNewWindow
if ($pipResult.ExitCode -ne 0) {
  throw "pip install failed with exit code $($pipResult.ExitCode)"
}

# Create config directory
$configDir = "$env:USERPROFILE\.siyarix"
if (-not (Test-Path $configDir)) {
  New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

Write-Host "$packageName $version installed successfully!"
Write-Host "Run 'siyarix --help' to get started."
