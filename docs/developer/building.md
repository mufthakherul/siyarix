# 🏗️ Building & Packaging Siyarix

Welcome to the build guide! Siyarix uses **hatchling** as its build system. This document covers building from source, packaging, and deploying. Since this is a growing personal project, the build scripts are designed to be as simple and useful as possible.

!!! note
    If you just want to install and use Siyarix, head over to the main installation guide. This page is primarily for developers helping out with the code!

## 🛠️ Build System

Siyarix uses `hatchling` for the build process.

```toml
[build-system]
requires = ["hatchling>=1.21.1"]
build-backend = "hatchling.build"
```

## 📦 Build from Source

Building the source code is straightforward:

```bash
# Install the build tool
pip install build

# Run the build process
python -m build

# 🎯 Your artifacts will be ready in the dist/ folder:
# dist/siyarix-1.0.0-py3-none-any.whl
# dist/siyarix-1.0.0.tar.gz
```

!!! tip "Development Installation"
    If you are actively developing Siyarix, install it in editable mode:
    ```bash
    pip install -e ".[all,cli,siem,dev]"
    ```

## 🚀 Publishing to PyPI

If you're a maintainer publishing a release:

```bash
pip install twine
python -m build

# ⚠️ Always test your release on TestPyPI first!
twine upload --repository testpypi dist/*

# ✅ Once verified, push to production
twine upload dist/*
```

## 🧩 Optional Extras

You can install specific "extras" depending on what you need.

| Extra | What it provides |
|-------|----------|
| `terminal` | UI dependencies like Rich, prompt_toolkit |
| `cli` | Typer, Rich, prompt_toolkit |
| `siem` | httpx for SIEM integrations |
| `autonomous` | Anthropic, Google Generative AI, and OpenAI SDKs |
| `api` | FastAPI and Uvicorn |
| `security` | Bandit, Safety, pip-audit |
| `all` | 🌟 All extras combined |
| `dev` | Pytest, ruff, mypy, pre-commit, build, twine |

### Examples:
```bash
pip install "siyarix[autonomous]"
pip install "siyarix[all]"
pip install "siyarix[dev]"
```

## 📁 Package Structure

A quick look at the directory layout:

```text
siyarix/
├── src/siyarix/          # Package source
├── tests/                # Test suite
├── packages/             # Platform-specific packaging
├── docs/                 # Documentation (Built with MkDocs)
├── scripts/              # Utility scripts
├── Dockerfile            # Docker build
└── pyproject.toml        # Build configuration & metadata
```

## 🌍 Platform Packages

Here's how to install Siyarix:

### 🐍 pip (Cross-Platform)

```bash
pip install siyarix
pip install "siyarix[all]"
```

### 🐳 Docker

I've also included a Dockerfile if you prefer containers.

```bash
# Build the image
docker build -t siyarix:latest .

# Run a quick command
docker run siyarix:latest scan --help
```

## 🔄 CI/CD Automation

I use GitHub Actions to automate testing and checks on PRs:
- Tests across Python 3.11+
- CodeQL analysis
- Dependabot for dependency updates

## 🛠️ Makefile Targets

I've wrapped common operations in a Makefile:

| Target | Description |
|--------|-------------|
| `make install` | Install dependencies |
| `make install-dev` | Install all development dependencies |
| `make test` | Run the test suite |
| `make lint` | Run Ruff linter |
| `make typecheck` | Run MyPy |
| `make build` | Build the sdist and wheel |
| `make docs` | Build the documentation |

!!! danger
    Always try to run `make test`, `make lint`, and `make typecheck` before pushing code.

## ✅ Publishing Checklist

Before shipping a new release:
1. Update version in `pyproject.toml`.
2. Document changes in `CHANGELOG.md`.
3. Run tests: `pytest`
4. Lint: `ruff check src/`
5. Verify types: `mypy src/siyarix/`
6. Build artifacts: `python -m build`
7. Upload to PyPI via twine.
8. Tag the release.
