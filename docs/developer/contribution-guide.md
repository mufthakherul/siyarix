# 🤝 Contribution Guide

Thank you for your interest in contributing to Siyarix! 🎉 I started this as a personal passion project, but **it is now officially public** and growing fast. I warmly welcome contributors of all skill levels! Whether it's fixing a typo in the documentation or adding a new AI provider, your contributions are what make this project better for everyone.

> 👋 **Heads Up:** To better support our growing community, Siyarix will soon be moving from my personal account to its very own dedicated GitHub organization (`siyarix/siyarix`). Don't worry, all links will seamlessly redirect!

Please read and follow these guidelines to help keep things organized.

!!! note
    I welcome all kinds of contributions! If you're planning a major change, please open an issue first so we can discuss the design before you spend time coding.

## 🧰 Prerequisites

Before diving in, make sure you have the following ready:
- **Python 3.11+**
- **Git**
- Familiarity with `asyncio`, Python type hints, and `pytest`
- A GitHub account

## 🛠️ Development Setup

Getting Siyarix running locally is pretty straightforward:

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

1. **Find or create an issue:** Let's chat about significant changes before you start work.
2. **Branch out:** Create a fresh branch for your work: `git checkout -b feat/my-awesome-feature`.
3. **Write code:** Make your changes, keeping the existing code conventions in mind.
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

- We follow **PEP 8**, enforced by **Ruff** (line length: 100).
- **Type hints** are highly encouraged, especially on public functions and methods (`disallow_untyped_defs`).
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

- Try to raise specific `SiyarixException` subclasses for domain errors.
- Avoid bare `except:` blocks when possible.
- Map exceptions to exit codes via `exit_code_for()` where appropriate.

## 📝 Commit Conventions

I try to follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Common Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `style`, `ci`, `chore`, `security`.

!!! info "DCO Sign-off Required!"
    Please include a `Signed-off-by` trailer certifying the [Developer Certificate of Origin](https://developercertificate.org/).
    You can do this by adding the `-s` flag to your commit command:
    `git commit -s -m "feat(core): add new feature"`

## 🔍 Pull Request Process

### Before Opening a PR
Check that your branch meets the requirements:
- All tests pass (`pytest -q`).
- Linter is happy (`ruff check`).
- Types are strict (`mypy src/siyarix/`).
- Added basic tests for new functionality.
- Updated documentation if behavior changed.

### Review Process
- I'll try to review PRs as soon as possible, but keep in mind this is a personal project.
- CI pipelines should pass.
- Feel free to ask questions if you get stuck!

## 🤖 Adding a New AI Provider

1. Create a provider profile in `src/siyarix/providers/profiles/`.
2. Register it inside the `ProviderManager`.
3. Add the corresponding API key environment variable to the setup documentation.
4. Write some basic tests in `tests/`.
5. Update the provider lists in the docs.

## 🛠️ Adding a New Tool Parser

1. Create your parser in `src/siyarix/parsers/`, implementing the `BaseParser` protocol.
2. Register it in `ParserRegistry`.
3. Provide a test fixture with sample tool output.
4. Add a test in `tests/`.

## 🔌 Plugins & Extensions

Siyarix supports loading plugins from `~/.siyarix/plugins/`. When contributing core plugins:
1. Follow existing patterns found in `src/siyarix/`.
2. Update `pyproject.toml` with any external dependencies under the appropriate `extras`.
3. Include tests.

## 🔐 Security Contributions

!!! danger "Please don't report security vulnerabilities via public GitHub issues!"
    Follow the [Security Policy](../security/vulnerability-reporting.md) for responsible disclosure.

- Standard PRs are welcome for hardening!

## 🧠 AI-Generated Code Disclosure

- You are responsible for all code you submit, regardless of how it was written.
- If your PR was heavily AI-generated, it's helpful to mention it in the description.
- It still needs to pass tests and linting.

## ⚖️ Licensing

By contributing, you agree your contributions will be licensed under the **AGPL-3.0-or-later**.
- Every source file should include this header:
  ```python
  # SPDX-License-Identifier: AGPL-3.0-or-later
  ```

!!! note
    If you are contributing on behalf of a company, please ensure you have authorization to contribute under the AGPL-3.0-or-later license.

Third-party plugins placed in `~/.siyarix/plugins/` are exempt from AGPL requirements. See our [Plugin Exception](../legal/plugin-exception.md).
