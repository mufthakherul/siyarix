## Development setup

This project targets Python 3.11+. The repository uses `hatchling` for build metadata but you can use a plain virtual environment too.

Recommended quick start (POSIX shells):

1) Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

2) Upgrade packaging tools and install the package in editable mode

```bash
python -m pip install --upgrade pip setuptools wheel
pip install -e .
```

3) Install test and linting tools

```bash
pip install pytest ruff
```

Optional (pre-commit):

```bash
pip install pre-commit
pre-commit install
```

4) Run tests

```bash
pytest -q
```

Alternative (using Hatch):

```bash
pip install hatch
hatch env create
hatch run pip install -e .
```

.env and secrets

- A placeholder `.env.example` exists at the repository root. NexSec also creates/uses a repo-root `.env` file for local API key syncing.
- You can store keys with `nexsec auth set-key <provider>` or the chat `/key` command — no manual env editing required.
- Never commit secrets (API keys) to the repository.

Linting

```bash
ruff check .
```

Notes

- If you need optional features (LLM integration, Rust acceleration) install extras declared in `pyproject.toml` (e.g., `pip install -e .[all]`).
- If you see issues during test runs, create a branch and open a PR with failing test output and a short note; I can help diagnose failures.
- Launching `nexsec` now opens the richer assistant-style landing screen, so you can verify the UX directly in development.
# Development Guide

### Developer Setup

To set up a local development environment:

```bash
git clone https://github.com/CosmicSec-Lab/nexsec.git
cd nexsec
python -m venv .venv
source .venv/bin/activate   # or .\.venv\Scripts\activate.ps1 on Windows
pip install -e '.[all]'
pytest -q
```

### Development Conventions

- **Code Quality**: We use Ruff for linting and formatting. Ensure your code follows the established project style.
- **Modularity**: When adding new functionality, prefer creating a new module or plugin rather than modifying the core execution logic.
- **Testing**: All new features must include comprehensive unit tests under the `tests/` directory using `pytest`.
- **Asynchrony**: Core logic is built on Python's `asyncio` for non-blocking subprocess management and model interaction.

### Architecture Highlights

- **`main.py`**: Multi-level CLI entry point with nested sub-apps.
- **`chat`**: Interactive AI assistant and REPL logic.
- **`planner`**: Task planning logic and model provider implementations.
- **`engine`**: The primary execution loop and dependency management.
- **`interpreter`**: Heuristic and model-driven instruction interpretation.
- **`parsers`**: Standardized adapters for external tool output.
- **`security_commands`**: Specialized SecOps command definitions.
