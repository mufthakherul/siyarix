# Building & Packaging

Siyarix supports multiple distribution formats using **hatchling** as the build system. This document covers building from source, package distribution channels, Docker, and platform-specific packaging.

## Build System

```toml
[build-system]
requires = ["hatchling>=1.21.1"]
build-backend = "hatchling.build"
```

## Build from Source

```bash
pip install build
python -m build
# Output in dist/
# dist/siyarix-1.0.0-py3-none-any.whl
# dist/siyarix-1.0.0.tar.gz
```

## Development Installation

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

## Optional Extras

| Extra | Provides |
|-------|----------|
| `terminal` | Rich, prompt_toolkit, Textual, pywin32 (Windows) |
| `cli` | Typer, Rich, prompt_toolkit, Textual, pywin32 |
| `siem` | httpx (SIEM forwarders) |
| `autonomous` | Anthropic, Google Generative AI, OpenAI SDKs |
| `openai` | OpenAI SDK |
| `gemini` | Google Generative AI SDK |
| `api` | FastAPI, Uvicorn, PyJWT |
| `anthropic` | Anthropic SDK |
| `security` | Bandit, Safety, pip-audit |
| `mobile` | Terminal extra + httpx |
| `windows` | Terminal extra + pywin32 + colorama |
| `all` | All extras combined |
| `dev` | Pytest, ruff, mypy, pre-commit, build, twine, bandit, safety, pip-audit |

```bash
pip install "siyarix[autonomous]"
pip install "siyarix[api]"
pip install "siyarix[all]"
pip install "siyarix[dev]"
```

## Package Structure

```
siyarix/
├── src/siyarix/          # Package source (80+ modules)
├── tests/                # Test suite (110+ test files)
├── packages/             # Platform-specific packages
│   ├── homebrew/         # Homebrew formula (siyarix.rb)
│   ├── winget/           # Winget manifest
│   ├── chocolatey/       # Chocolatey package
│   └── deb/              # Debian/Ubuntu packaging
├── docs/                 # Documentation (MkDocs Material)
├── scripts/              # Utility scripts
├── Dockerfile            # Multi-stage Docker build (python, kali, parrot)
├── docker-compose.yml    # Docker Compose with Redis, OpenTelemetry
└── pyproject.toml        # Build config & metadata
```

## Platform Packages

### pip (all platforms)

```bash
pip install siyarix
pip install "siyarix[all]"
```

### Homebrew (macOS)

```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### Winget (Windows)

```bash
winget install Mufthakherul.Siyarix
```

### Chocolatey (Windows)

```bash
choco install siyarix
```

### Debian/Ubuntu/Kali

```bash
sudo dpkg -i packages/deb/siyarix_1.0.0-1_all.deb
```

### Docker

```bash
docker build -t siyarix:latest .                             # Production
docker build --target development -t siyarix:dev .           # Development
docker compose up                                             # Full stack with Redis
docker run siyarix:latest scan --help                         # Run command
docker run -v ~/.siyarix:/root/.siyarix siyarix:latest run "scan x"  # With config
```

## CI/CD

Siyarix uses **47 GitHub Actions workflows** covering:

- Continuous integration (CI) across Python 3.11, 3.12, 3.13 on Linux, Windows, macOS
- Docker image build and publish
- Release automation
- CodeQL security analysis
- SBOM generation
- Secret scanning
- Documentation deployment (MkDocs)
- Smoke tests and chaos testing
- Benchmarks
- Dependabot dependency monitoring

## Makefile Targets

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
| `make security` | Bandit + pip-audit |
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
| `make docs` | Build documentation site |
| `make docs-serve` | Serve docs locally |

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
10. Tag release: `git tag v1.0.0 && git push --tags`
11. Build and publish Docker image
12. Update Homebrew formula
13. Update Winget/Chocolatey manifests
