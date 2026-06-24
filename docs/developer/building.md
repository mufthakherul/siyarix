# 🏗️ Building & Packaging Siyarix

Welcome to the build guide! Siyarix supports multiple distribution formats and uses **hatchling** as its robust build system. This document covers everything you need to know about building from source, utilizing package distribution channels, deploying via Docker, and handling platform-specific packaging.

> [!NOTE]
> If you're just looking to install Siyarix for regular use, head over to our main installation guide. This page is primarily for developers, maintainers, and packagers!

## 🛠️ Build System

Siyarix relies on modern Python standards, specifically `hatchling`, for an efficient and clean build process.

```toml
[build-system]
requires = ["hatchling>=1.21.1"]
build-backend = "hatchling.build"
```

## 📦 Build from Source

Ready to compile the source code yourself? It's straightforward:

```bash
# Install the build tool
pip install build

# Run the build process
python -m build

# 🎯 Your artifacts will be ready in the dist/ folder:
# dist/siyarix-1.0.0-py3-none-any.whl
# dist/siyarix-1.0.0.tar.gz
```

> [!TIP]
> **Development Installation**
> If you are actively developing Siyarix, install it in editable mode with all the necessary extras:
> ```bash
> pip install -e ".[all,cli,siem,dev]"
> ```

## 🚀 Publishing to PyPI

When it's time to release a new version to the world, we use `twine`:

```bash
pip install twine
python -m build

# ⚠️ Always test your release on TestPyPI first!
twine upload --repository testpypi dist/*

# ✅ Once verified, push to production
twine upload dist/*
```

## 🧩 Optional Extras

Siyarix is modular! You can install specific "extras" to tailor the platform to your needs without bloat.

| Extra | What it provides |
|-------|----------|
| `terminal` | Rich, prompt_toolkit, Textual, pywin32 (Windows) for an enhanced UI |
| `cli` | Typer, Rich, prompt_toolkit, Textual, pywin32 |
| `siem` | httpx for SIEM forwarder integrations |
| `autonomous` | Anthropic, Google Generative AI, and OpenAI SDKs |
| `openai` | OpenAI SDK |
| `gemini` | Google Generative AI SDK |
| `api` | FastAPI, Uvicorn, PyJWT for exposing the Siyarix API |
| `anthropic` | Anthropic SDK |
| `security` | Bandit, Safety, pip-audit for self-scanning |
| `mobile` | Terminal extra + httpx |
| `windows` | Terminal extra + pywin32 + colorama |
| `all` | 🌟 All extras combined |
| `dev` | Pytest, ruff, mypy, pre-commit, build, twine, bandit, safety, pip-audit |

### Examples:
```bash
pip install "siyarix[autonomous]"
pip install "siyarix[api]"
pip install "siyarix[all]"
pip install "siyarix[dev]"
```

## 📁 Package Structure

Here is a bird's-eye view of how Siyarix is structured on disk:

```text
siyarix/
├── src/siyarix/          # Package source (80+ core modules)
├── tests/                # Test suite (110+ comprehensive test files)
├── packages/             # Platform-specific packaging manifests
│   ├── homebrew/         # Homebrew formula (siyarix.rb) for macOS
│   ├── winget/           # Winget manifest for Windows
│   ├── chocolatey/       # Chocolatey package for Windows
│   └── deb/              # Debian/Ubuntu (.deb) packaging
├── docs/                 # Documentation (Built with MkDocs Material)
├── scripts/              # Handy utility scripts
├── Dockerfile            # Multi-stage Docker build (python, kali, parrot)
├── docker-compose.yml    # Docker Compose setup including Redis & OpenTelemetry
└── pyproject.toml        # Build configuration & metadata
```

## 🌍 Platform Packages

We strive to meet you where you are. Here's how to install Siyarix across different ecosystems:

### 🐍 pip (Cross-Platform)

```bash
pip install siyarix
pip install "siyarix[all]"
```

### 🍎 Homebrew (macOS)

```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

### 🪟 Winget & Chocolatey (Windows)

```bash
# Using Winget
winget install Mufthakherul.Siyarix

# Using Chocolatey
choco install siyarix
```

### 🐧 Debian / Ubuntu / Kali

```bash
sudo dpkg -i packages/deb/siyarix_1.0.0-1_all.deb
```

### 🐳 Docker

Docker is a first-class citizen in the Siyarix ecosystem.

```bash
# Build the production image
docker build -t siyarix:latest .

# Build for development
docker build --target development -t siyarix:dev .

# Start the full stack (including Redis)
docker compose up

# Run a quick command
docker run siyarix:latest scan --help

# Run with your local configuration mounted
docker run -v ~/.siyarix:/root/.siyarix siyarix:latest run "scan x"
```

## 🔄 CI/CD Automation

Siyarix is heavily automated! We rely on **47 GitHub Actions workflows** to ensure stability and security:

- **Continuous Integration (CI):** Tests across Python 3.11, 3.12, and 3.13 on Linux, Windows, and macOS.
- **Docker:** Automated image builds and publishing.
- **Release Automation:** Seamless version bumping and tagging.
- **Security:** CodeQL analysis, SBOM generation, and secret scanning.
- **Documentation:** Auto-deployment to our MkDocs site.
- **Resilience:** Smoke tests, chaos testing, and benchmark runs.
- **Maintenance:** Dependabot keeps our dependencies fresh.

## 🛠️ Makefile Targets

For your convenience, we've wrapped common operations in a Makefile:

| Target | Description |
|--------|-------------|
| `make install` | Install production dependencies |
| `make install-dev` | Install all development dependencies |
| `make test` | Run the full test suite with coverage |
| `make test-quick` | Run quick tests (skipping the slow ones) |
| `make lint` | Run the Ruff linter |
| `make lint-fix` | Run Ruff with auto-fixing enabled |
| `make typecheck` | Run MyPy for static type analysis |
| `make format` | Run the Ruff formatter |
| `make security` | Run Bandit & pip-audit |
| `make coverage` | Generate test coverage reports |
| `make build` | Build the sdist and wheel packages |
| `make build-deb` | Build a Debian `.deb` package |
| `make build-docker` | Build the Docker image |
| `make docker-up` | Spin up Docker services |
| `make docker-down` | Tear down Docker services |
| `make clean` | Sweep away build artifacts |
| `make pre-commit` | Execute pre-commit hooks manually |
| `make publish-pypi` | Publish the release to PyPI |
| `make publish-testpypi`| Publish the release to TestPyPI |
| `make docs` | Build the documentation site locally |
| `make docs-serve` | Serve the docs on a local webserver |

> [!CAUTION]
> Always run `make test`, `make lint`, and `make typecheck` before pushing your code to avoid CI failures.

## ✅ Publishing Checklist

Maintainers, follow this checklist before shipping a new release:

1. Update the version number in `pyproject.toml`.
2. Document the changes in `CHANGELOG.md`.
3. Run the full test suite: `pytest --cov=siyarix`
4. Ensure linting passes: `ruff check src/`
5. Verify types: `mypy src/siyarix/`
6. Build the artifacts: `python -m build`
7. Upload to TestPyPI: `twine upload --repository testpypi dist/*`
8. Verify the installation from TestPyPI.
9. Upload to production PyPI: `twine upload dist/*`
10. Tag the release: `git tag v1.0.0 && git push --tags`
11. Build and push the official Docker image.
12. Update the macOS Homebrew formula.
13. Update Windows Winget and Chocolatey manifests.
