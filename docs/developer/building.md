# Building & Packaging

## Building from source

```bash
# Install build dependencies
pip install build hatchling

# Build wheel and source distribution
python -m build

# Output in dist/
# dist/siyarix-3.0.0-py3-none-any.whl
# dist/siyarix-3.0.0.tar.gz
```

## Development installation

```bash
# Editable install (changes take effect immediately)
pip install -e ".[all,cli,siem,dev]"
```

## Publishing to PyPI

```bash
# Install publishing tools
pip install twine

# Build
python -m build

# Upload to TestPyPI first
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

## Package structure

```
siyarix/
├── src/siyarix/      # Package source
├── tests/             # Test suite
├── packages/          # Platform-specific packages
│   ├── npm/           # npm launcher package
│   ├── homebrew/      # Homebrew formula
│   └── winget/        # Winget manifest
├── Dockerfile         # Docker build
├── docker-compose.yml # Docker Compose
└── pyproject.toml     # Build configuration
```

## Build system

Siyarix uses **Hatchling** as the build backend:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

## Platform packages

### Homebrew

The Homebrew formula is at `packages/homebrew/siyarix.rb`. To test locally:

```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### npm

The npm package at `packages/npm/` provides a Node.js launcher:

```bash
cd packages/npm
npm publish --access public
```

### Winget

The Winget manifest at `packages/winget/` follows the Microsoft winget-create format.

## Docker

```bash
# Build production image
docker build -t siyarix:latest .

# Build development image
docker build --target development -t siyarix:dev .

# Run with compose
docker compose up

# Run a command
docker run siyarix:latest scan --help
```
