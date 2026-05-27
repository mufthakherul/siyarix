# Contribution Guide

## Prerequisites

- Python 3.11+
- Git
- Basic familiarity with asyncio, typing, and pytest

## Setup

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/siyarix.git
cd siyarix

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .\.venv\Scripts\Activate.ps1  # Windows

# Install in development mode with dev dependencies
pip install -e ".[all,cli,siem,dev]"
```

## Development workflow

1. **Pick an issue** from the GitHub issue tracker
2. **Create a branch**: `git checkout -b feat/my-feature`
3. **Make changes** following the code conventions
4. **Run tests**: `pytest`
5. **Lint**: `ruff src/ tests/`
6. **Type check**: `mypy src/siyarix/`
7. **Commit** with a descriptive message
8. **Push** and open a pull request

## Code conventions

### Style

- Follow PEP 8 as enforced by Ruff (line length: 100)
- Use type hints for all public functions and methods
- Use `from __future__ import annotations` at the top of every module
- Prefer dataclasses over plain dicts for structured data
- Use `asyncio` for I/O-bound operations

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Classes | PascalCase | `ExecutionEngine` |
| Functions | snake_case | `get_health()` |
| Variables | snake_case | `scan_target` |
| Constants | UPPER_CASE | `DEFAULTS` |
| Private | leading underscore | `_get_engine()` |

### Imports

Group imports in this order (separated by blank lines):

1. Standard library (`os`, `sys`, `asyncio`)
2. Third-party (`typer`, `rich`, `pydantic`)
3. Internal (`siyarix.config`, `.audit_log`)

### Error handling

- Raise `SiyarixException` subclasses for domain errors
- Use `exit_code_for()` to map exceptions to exit codes
- Do not catch bare `Exception`

### Testing

- Write tests using `pytest` and `pytest-asyncio`
- Place tests in `tests/` mirroring the source structure
- Use fixtures for common setup (mock providers, temp directories)
- Target minimum 75% coverage

```python
# Example test
async def test_planner_parse_simple_command():
    planner = TaskPlanner()
    result = await planner.plan("scan 10.0.0.1")
    assert result is not None
    assert "target" in result
```

## Pull request process

1. Ensure all CI checks pass (tests, lint, type check)
2. Update documentation if adding/changing user-facing features
3. Add tests for new functionality
4. Keep PRs focused — one feature/fix per PR

## Project governance

See [GOVERNANCE.md](../../GOVERNANCE.md) for decision-making and maintainer structure.

## Code of conduct

All contributors must follow the [Code of Conduct](../../CODE_OF_CONDUCT.md).
