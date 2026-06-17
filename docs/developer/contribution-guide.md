# Contribution Guide

Thank you for your interest in contributing to Siyarix! Whether you're fixing a bug, adding a feature, improving documentation, or reporting an issue — you're welcome here.

---

## Prerequisites

- Python 3.11+
- Git
- Basic familiarity with asyncio, type hints, and pytest
- A GitHub account

## Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR-USERNAME/siyarix.git
cd siyarix

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .\.venv\Scripts\Activate.ps1  # Windows

# Install in development mode with all extras
pip install -e ".[all,cli,siem,dev]"
```

## Development Workflow

1. **Find or create an issue** — Discuss your planned changes before investing significant effort
2. **Create a branch**: `git checkout -b feat/my-feature`
3. **Make changes** following the code conventions below
4. **Run quality checks**:
   ```bash
   pytest                    # Run tests
   ruff check src/ tests/    # Lint
   mypy src/siyarix/         # Type check
   ```
5. **Commit** with a conventional commit message
6. **Push and open a pull request** targeting the `main` branch

## Code Conventions

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
| Private | Leading underscore | `_get_engine()` |

### Imports

Group imports in this order, separated by blank lines:

1. Standard library (`os`, `sys`, `asyncio`)
2. Third-party (`typer`, `rich`, `pydantic`)
3. Internal (`siyarix.config`, `.audit_log`)

### Error Handling

- Raise `SiyarixException` subclasses for domain errors
- Use specific exception types; avoid bare `except:`
- Map exceptions to exit codes via `exit_code_for()`

### Async

- Use `asyncio` for I/O-bound operations
- Avoid blocking the event loop
- Use `asyncio.gather()` for concurrent operations

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Usage |
|------|-------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code changes that neither fix nor add |
| `perf` | Performance improvements |
| `style` | Formatting, linting (no logic change) |
| `ci` | CI/CD configuration changes |
| `chore` | Build, dependencies, tooling |
| `security` | Security fixes or hardening |

### Examples

```
fix(executor): handle tool-not-found gracefully
docs: update installation guide for Windows
test: add regression test for provider failover
security: fix credential vault AES-GCM padding
```

### DCO Sign-off

Sign commits off to certify the Developer Certificate of Origin:

```bash
git commit -s -m "type(scope): description"
```

This adds a `Signed-off-by:` trailer.

## Pull Request Process

### Before Opening

- Ensure all existing tests pass: `pytest -q`
- Ensure lint is clean: `ruff check src/ tests/`
- Ensure type checks pass: `mypy src/siyarix/`
- Add tests for new functionality or bug fixes
- Update or add documentation for changed behavior

### PR Description

Include:

- **What** this PR changes
- **Why** these changes are needed (link to issue if applicable)
- **How** the changes were tested
- **Screenshots** or logs for UI/behavior changes (if relevant)

### Review Process

1. At least one maintainer review is required
2. CI must pass (tests, lint, type check, security scan)
3. Address review feedback promptly
4. Maintainers may merge once all checks pass and reviews are approved

## Adding a New AI Provider

1. Create a new provider profile in `src/siyarix/providers/profiles/` following the existing patterns
2. Register the provider in the `ProviderManager`
3. Add the API key environment variable to the setup documentation
4. Add tests in `tests/test_providers.py`
5. Update the provider list in relevant documentation files

## Adding a New Tool Parser

1. Create a new parser file in `src/siyarix/parsers/` implementing the `BaseParser` protocol
2. Register the parser in `ParserRegistry`
3. Add test fixtures with sample tool output
4. Add tests in `tests/test_parsers/`
5. Document the parser in the tool execution docs

## Security Contributions

We deeply appreciate security researchers who help us improve Siyarix:

- Follow the [Security Policy](../../SECURITY.md) for vulnerability disclosure
- For non-critical security hardening, standard PRs are welcome
- We will credit security contributors in release notes (with permission)

## Documentation Contributions

Documentation improvements are always welcome:

- Fix typos and clarify unclear sections
- Add examples for under-documented features
- Keep documentation consistent with current behavior
- If you change CLI behavior or slash commands, update the corresponding docs

## AI-Generated Code Disclosure

We welcome contributions regardless of how they are authored, including with AI assistance. However:

- You are responsible for any code you submit, regardless of how it was generated
- Disclose AI assistance in your PR description if the majority of the contribution was AI-generated
- AI-generated code must still follow all project coding standards and include appropriate tests
- The project maintainers reserve the right to request modifications to AI-generated contributions

## Community & Communication

- **GitHub Issues** — Bug reports, feature requests, discussions
- **GitHub Discussions** — General questions, ideas, community support
- **Pull Requests** — Code contributions

We strive to be responsive and kind. There are no stupid questions.

## Licensing

### Contribution license

By contributing to Siyarix, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0 or later](../../LICENSE) (SPDX: `AGPL-3.0-or-later`). You must have the right to license your contributions under these terms.

### DCO and contribution certification

Every commit must include a `Signed-off-by` trailer certifying the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "feat(scope): description"
```

This certifies that you have the right to submit the work under the project license.

### For corporate contributors

If you are contributing as part of your employment:

- **Confirm your employer's policy** — Ensure your employer allows contributions to AGPL projects. Many companies have open-source contribution policies; check with your legal or open-source team first.
- **Employer permission** — By signing off on a commit, you represent that you have obtained any necessary authorization from your employer to contribute under AGPL-3.0-or-later.
- **No proprietary code** — Do not submit code that your employer considers proprietary or that you discovered through your employment relationship unless you have explicit written permission.
- **GitHub account** — Use your personal GitHub account (not a shared or employer-controlled account) unless your employer's policy expressly permits otherwise.

### Plugin exception

Third-party plugins loaded via `~/.siyarix/plugins/` are **not required** to be AGPL-licensed. See the [Plugin Exception](../legal/plugin-exception.md) for details.

### SPDX header

Every source file must include an SPDX license identifier:

```python
# SPDX-License-Identifier: AGPL-3.0-or-later
```

---

*Happy hacking, and thank you for helping make Siyarix better.*

*SPDX-License-Identifier: AGPL-3.0-or-later*
