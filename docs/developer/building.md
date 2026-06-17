# Building & Packaging

Siyarix supports multiple distribution formats: Python packages (sdist/wheel), Docker images, npm launcher, Homebrew formula, Debian packages, Winget manifest, and Chocolatey package.

---

## Building from Source

```bash
# Install build dependencies
pip install build hatchling

# Build wheel and source distribution
python -m build

# Output in dist/
# dist/siyarix-3.0.0-py3-none-any.whl
# dist/siyarix-3.0.0.tar.gz
```

## Development Installation

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

## Build System

Siyarix uses **Hatchling** as the build backend:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

## Package Structure

```
siyarix/
├── src/siyarix/      # Package source (78+ modules)
├── tests/             # Test suite (102+ test files)
├── packages/          # Platform-specific packages
│   ├── npm/           # npm launcher package
│   ├── homebrew/      # Homebrew formula
│   ├── winget/        # Winget manifest
│   ├── chocolatey/    # Chocolatey package
│   ├── deb/           # Debian/Ubuntu packaging
│   ├── harmonyos/     # HarmonyOS installer
│   └── rust_parsers/  # Rust PyO3 parsers
├── docs/              # Documentation (MkDocs Material)
├── scripts/           # Utility scripts
├── Dockerfile         # Multi-stage Docker build
├── docker-compose.yml # Docker Compose orchestration
└── pyproject.toml     # Build configuration & metadata
```

## Platform Packages

### Homebrew

The Homebrew formula is at `packages/homebrew/siyarix.rb`:

```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### npm

The npm package at `packages/npm/` provides a Node.js launcher that auto-installs the Python package:

```bash
cd packages/npm
npm publish --access public
```

Usage: `npx @mufthakherul/siyarix --help`

### Winget

The Winget manifest at `packages/winget/` follows the Microsoft winget-create format:

```bash
winget install Mufthakherul.Siyarix
```

### Chocolatey

The Chocolatey package at `packages/chocolatey/`:

```bash
choco install siyarix
```

### Debian/Ubuntu

The .deb package at `packages/deb/`:

```bash
sudo dpkg -i packages/deb/siyarix_3.0.0-1_all.deb
```

## Docker

```bash
# Build production image
docker build -t siyarix:latest .

# Build development image
docker build --target development -t siyarix:dev .

# Run with compose (worker, dashboard, Redis, OpenTelemetry)
docker compose up

# Run a command
docker run siyarix:latest scan --help

# Run with mounted config
docker run -v ~/.siyarix:/root/.siyarix siyarix:latest run "scan example.com"
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make install` | Install production dependencies |
| `make install-dev` | Install all dev dependencies |
| `make test` | Run all tests with coverage |
| `make test-quick` | Run quick tests (exclude slow) |
| `make lint` | Run ruff linter |
| `make lint-fix` | Run ruff linter with auto-fix |
| `make typecheck` | Run mypy type checking |
| `make format` | Run ruff formatter |
| `make security` | Run bandit + trufflehog + gitleaks + pip-audit |
| `make coverage` | Run tests with coverage report |
| `make build` | Build Python sdist + wheel |
| `make build-npm` | Build npm package |
| `make build-deb` | Build Debian .deb package |
| `make build-docker` | Build Docker image |
| `make docker-up` | Start all Docker services |
| `make docker-down` | Stop all Docker services |
| `make clean` | Clean build artifacts and caches |
| `make pre-commit` | Run all pre-commit hooks |
| `make publish-pypi` | Publish to PyPI |
| `make publish-testpypi` | Publish to TestPyPI |

## Publishing Checklist

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `pytest --cov=siyarix`
4. Run lint: `ruff check src/`
5. Run type check: `mypy src/siyarix/`
6. Build: `python -m build`
7. Upload to TestPyPI: `twine upload --repository testpypi dist/*`
8. Test install from TestPyPI
9. Upload to PyPI: `twine upload dist/*`
10. Tag release: `git tag v3.0.0 && git push --tags`
11. Build and publish Docker image
12. Update Homebrew formula
13. Publish npm package
14. Update Winget/Chocolatey manifests
