# Development Guide

### Developer Setup

To set up a local development environment:

```bash
git clone https://github.com/CosmicSec-Lab/siyarix.git
cd siyarix
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

- **`planner`**: Task planning logic and model provider implementations.
- **`engine`**: The primary execution loop and dependency management.
- **`interpreter`**: Heuristic and model-driven instruction interpretation.
- **`parsers`**: Standardized adapters for external tool output.
