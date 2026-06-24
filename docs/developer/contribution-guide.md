# 🤝 Contribution Guide

Thank you for your interest in contributing to Siyarix! 🎉 Whether you are a seasoned security professional, a Python developer, a documentation writer, or an enthusiastic student, your contributions are what help build the future of AI-native security orchestration. 

Please read and follow these guidelines to ensure a smooth and collaborative experience.

> [!NOTE]
> We welcome all kinds of contributions—from typo fixes to entirely new AI provider integrations! If you're planning a major change, please open an issue first so we can discuss the design.

## 🧰 Prerequisites

Before diving in, make sure you have the following ready:
- **Python 3.11+**
- **Git**
- Familiarity with `asyncio`, Python type hints, and `pytest`
- A GitHub account

## 🛠️ Development Setup

Getting Siyarix running locally is a breeze:

```bash
# 1. Clone your fork
git clone https://github.com/YOUR-USERNAME/siyarix.git
cd siyarix

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate         # Linux/macOS
# .\.venv\Scripts\Activate.ps1    # Windows

# 3. Install in editable mode with development dependencies
pip install -e ".[all,cli,siem,dev]"
```

### ✅ Verify Your Setup

Ensure everything is configured correctly before writing code:

```bash
pytest -q           # Run the test suite
ruff check .        # Check for linting errors
mypy src/siyarix/   # Verify static type checking
```

## 🔄 Contribution Workflow

1. **Find or create an issue:** Discuss significant changes with maintainers before starting work.
2. **Branch out:** Create a fresh branch for your work: `git checkout -b feat/my-awesome-feature`.
3. **Write code:** Make your changes, ensuring you follow our code conventions.
4. **Run Quality Checks:** 
   ```bash
   pytest                          # Ensure tests pass
   ruff check src/ tests/          # Ensure code is lint-free
   mypy src/siyarix/               # Ensure type strictness
   ```
5. **Commit:** Use conventional commit messages and ensure your commit is DCO signed (`git commit -s`).
6. **Push & PR:** Push your branch and open a Pull Request targeting the `main` branch.

## 📏 Code Conventions

### 🎨 Style

- We follow **PEP 8**, strictly enforced by **Ruff** (line length: 100).
- **Type hints** are mandatory on all public functions and methods (`disallow_untyped_defs`).
- Include `from __future__ import annotations` at the top of every module.
- Use **Dataclasses** for structured data.
- Prefer `asyncio` for any I/O-bound operations.

### 🏷️ Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Classes | PascalCase | `ExecutionEngine` |
| Functions | snake_case | `get_health()` |
| Variables | snake_case | `scan_target` |
| Constants | UPPER_CASE | `DEFAULTS` |
| Private | Leading underscore | `_get_engine()` |

### 📦 Imports

Organize your imports in blocks, separated by blank lines:
1. Standard library (e.g., `os`, `sys`, `asyncio`)
2. Third-party (e.g., `typer`, `rich`, `pydantic`)
3. Internal Siyarix modules (e.g., `siyarix.config`, `.audit_log`)

### ⚠️ Error Handling

- Always raise specific `SiyarixException` subclasses for domain errors.
- **Never** use bare `except:` blocks.
- Map exceptions correctly to exit codes via `exit_code_for()`.

## 📝 Commit Conventions

We strictly follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Common Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `style`, `ci`, `chore`, `security`.

> [!IMPORTANT]
> **DCO Sign-off Required!**
> Every single commit must include a `Signed-off-by` trailer certifying the [Developer Certificate of Origin](https://developercertificate.org/).
> You can easily do this by adding the `-s` flag to your commit command:
> `git commit -s -m "feat(core): add awesome new planner"`

## 🔍 Pull Request Process

### Before Opening a PR
Ensure your branch meets all requirements:
- All tests pass (`pytest -q`).
- Linter is happy (`ruff check`).
- Types are strict (`mypy src/siyarix/`).
- You've added tests for new functionality.
- You've updated documentation if behavior changed.

### Review Process
- At least one maintainer review is required.
- CI pipelines must pass completely.
- Address review feedback promptly. Do not force-push after a review has started; add new commits instead.

## 🤖 Adding a New AI Provider

1. Create a provider profile in `src/siyarix/providers/profiles/`.
2. Register it inside the `ProviderManager`.
3. Add the corresponding API key environment variable to the setup documentation.
4. Write tests in `tests/test_providers.py`.
5. Update the provider lists in the general documentation.

## 🛠️ Adding a New Tool Parser

1. Create your parser in `src/siyarix/parsers/`, ensuring it implements the `BaseParser` protocol.
2. Register it in `ParserRegistry`.
3. Provide test fixtures containing sample tool output.
4. Add comprehensive tests in `tests/test_parsers/`.

## 🔌 Plugins & Extensions

Siyarix supports dynamic plugins out of `~/.siyarix/plugins/`. When contributing core plugins:
1. Follow existing patterns found in `src/siyarix/`.
2. Register your module through the correct registry.
3. Update `pyproject.toml` with any external dependencies under the appropriate `extras`.
4. Include tests!

## 🔐 Security Contributions

> [!CAUTION]
> **Never report security vulnerabilities via public GitHub issues!**
> Please follow our [Security Policy](../security/vulnerability-reporting.md) for responsible disclosure.

- Standard Pull Requests are always welcome for non-critical hardening!
- Security contributors will be credited in our release notes (with permission).

## 🧠 AI-Generated Code Disclosure

- You are fundamentally responsible for all code you submit, regardless of how it was authored.
- If the majority of your PR was AI-generated, **disclose this in the PR description**.
- AI-generated code must meet all human standards (tests, linting, docs). Maintainers reserve the right to request modifications.

## ⚖️ Licensing

By contributing, you agree that your contributions will be licensed under the **AGPL-3.0-or-later**.
- Every source file must include this header:
  ```python
  # SPDX-License-Identifier: AGPL-3.0-or-later
  ```

> [!NOTE]
> **Corporate Contributors:** Please ensure you have authorization from your employer to contribute under the AGPL-3.0-or-later license before submitting code.

Third-party plugins placed in `~/.siyarix/plugins/` are an exception and are not required to be AGPL-licensed. See our [Plugin Exception](../legal/plugin-exception.md) for details.
