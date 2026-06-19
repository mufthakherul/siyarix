# Building & Packaging

Siyarix supports multiple distribution formats using **hatchling** as the build system.

## Build from source

```bash
pip install build hatchling
python -m build
# Output in dist/
# dist/siyarix-3.0.0-py3-none-any.whl
# dist/siyarix-3.0.0.tar.gz
```

## Development installation

```bash
pip install -e ".[all,cli,siem,dev]"
```

## Publish to PyPI

```bash
pip install twine
python -m build
twine upload --repository testpypi dist/*   # Test first
twine upload dist/*                         # Production
```

## Build system

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

## Package structure

```
siyarix/
├── src/siyarix/          # Package source (78+ modules)
├── tests/                # Test suite
├── packages/             # Platform-specific packages

│   ├── homebrew/         # Homebrew formula
│   ├── winget/           # Winget manifest
│   ├── chocolatey/       # Chocolatey package
│   ├── deb/              # Debian/Ubuntu packaging
│   ├── harmonyos/        # HarmonyOS installer
│   └── rust_parsers/     # Rust PyO3 parsers
├── docs/                 # Documentation (MkDocs Material)
├── scripts/              # Utility scripts
├── Dockerfile            # Multi-stage Docker build
├── docker-compose.yml    # Docker Compose orchestration
└── pyproject.toml        # Build config & metadata
```

## Platform packages

### Homebrew

```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### Winget

```bash
winget install Mufthakherul.Siyarix
```

### Chocolatey

```bash
choco install siyarix
```

### Debian/Ubuntu

```bash
sudo dpkg -i packages/deb/siyarix_3.0.0-1_all.deb
```

## Docker

```bash
docker build -t siyarix:latest .                             # Production
docker build --target development -t siyarix:dev .           # Development
docker compose up                                             # Full stack
docker run siyarix:latest scan --help                         # Run command
docker run -v ~/.siyarix:/root/.siyarix siyarix:latest run "scan x"  # With config
```

## Makefile targets

| Target | Description |
|--------|-------------|
| `make install` | Install production dependencies |
| `make install-dev` | Install all dev dependencies |
| `make test` | Run all tests with coverage |
| `make test-quick` | Quick tests (exclude slow) |
| `make lint` | Run ruff linter |
| `make lint-fix` | Run ruff with auto-fix |
| `make typecheck` | Run mypy |
| `make format` | Run ruff formatter |
| `make security` | Bandit + trufflehog + gitleaks + pip-audit |
| `make coverage` | Tests with coverage report |
| `make build` | Build sdist + wheel |
| `make build-deb` | Build .deb package |
| `make build-docker` | Build Docker image |
| `make docker-up` | Start Docker services |
| `make docker-down` | Stop Docker services |
| `make clean` | Clean build artifacts |
| `make pre-commit` | Run pre-commit hooks |
| `make publish-pypi` | Publish to PyPI |
| `make publish-testpypi` | Publish to TestPyPI |

## Publishing checklist

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
13. Update Winget/Chocolatey manifests
