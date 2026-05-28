# Contributing to Siyarix

First off, thank you for considering contributing to Siyarix! Whether you are a seasoned security engineer, a Python developer, a student exploring open source, or a documentation enthusiast — you are welcome here.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Commit Conventions](#commit-conventions)
- [Issue Reporting](#issue-reporting)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Security Contributions](#security-contributions)
- [Plugin & Module Contributions](#plugin--module-contributions)
- [Documentation Contributions](#documentation-contributions)
- [AI-Generated Code Disclosure](#ai-generated-code-disclosure)
- [Community & Communication](#community--communication)

---

## Code of Conduct

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to a welcoming, harassment-free experience for everyone.

---

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- A GitHub account

### Setup

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/siyarix.git
cd siyarix
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .\.venv\Scripts\activate.ps1  # Windows
pip install -e ".[all,cli,siem]" pytest ruff mypy
```

### Verify

```bash
pytest -q           # Run tests
ruff check .        # Lint check
mypy src/siyarix/   # Type check
```

---

## Contribution Workflow

1. **Find or create an issue** — Discuss your planned changes before investing significant effort.
2. **Fork and branch** — Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. **Make your changes** — Keep them focused and well-tested.
4. **Run quality checks**:
   ```bash
   pytest -q
   ruff check .
   mypy src/siyarix/
   ```
5. **Commit** — Follow [commit conventions](#commit-conventions).
6. **Push and open a PR** — Target the `main` branch.

---

## Coding Standards

- **Language**: Python 3.11+
- **Style**: Follow existing code conventions — we use [Ruff](https://docs.astral.sh/ruff/) for consistent formatting.
- **Type Hints**: All public functions and methods must have type annotations.
- **Documentation**: Docstrings for public APIs (Google or NumPy style).
- **Testing**: New features must include tests. Bug fixes should include regression tests.
- **Imports**: Standard library → third-party → local imports (grouped with blank lines).
- **Error Handling**: Use specific exception types; avoid bare `except:`.
- **Async**: Use `asyncio` for I/O-bound operations; avoid blocking the event loop.

Run formatting:
```bash
ruff format .
```

---

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type     | Usage                                     |
|----------|-------------------------------------------|
| `feat`   | A new feature                             |
| `fix`    | A bug fix                                 |
| `docs`   | Documentation changes                     |
| `test`   | Adding or updating tests                  |
| `refactor` | Code changes that neither fix nor add  |
| `perf`   | Performance improvements                  |
| `style`  | Formatting, linting (no logic change)     |
| `ci`     | CI/CD configuration changes               |
| `chore`  | Build, dependencies, tooling              |
| `security` | Security fixes or hardening            |

### Examples

```
feat(chat): add /work-mode persona switching
fix(executor): handle tool-not-found gracefully
docs: update installation guide for Windows
test: add regression test for issue #142
security: fix credential vault AES-GCM padding
```

### DCO Sign-off

To keep contribution provenance clear, sign commits off with:

```bash
git commit -s -m "type(scope): message"
```

This adds a `Signed-off-by:` trailer (Developer Certificate of Origin).

---

## Issue Reporting

### Bug Reports

When filing a bug report, include:

- **Expected behavior** vs **actual behavior**
- **Steps to reproduce** (minimal, complete, verifiable)
- **Environment**: OS, Python version, Siyarix version
- **Relevant logs or error messages** (sanitized)
- **Impact assessment**: how does this affect your use case?

### Feature Requests

- Describe the problem you're trying to solve, not just the solution you want.
- Include relevant use cases and examples of desired behavior.
- Search existing issues to avoid duplicates.

### Security Issues

**Do not** file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for private disclosure.

---

## Pull Request Guidelines

### Before Opening

- Ensure all existing tests pass: `pytest -q`
- Ensure lint is clean: `ruff check .`
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

1. At least one maintainer review is required.
2. CI must pass (tests, lint, type check, security scan).
3. Address review feedback promptly.
4. Maintainers may merge once all checks pass and reviews are approved.

### After Merge

- Celebrate responsibly 🎉
- Your changes will be included in the next release.

---

## Security Contributions

We deeply appreciate security researchers who help us improve Siyarix:

- Follow the [Security Policy](SECURITY.md) for vulnerability disclosure.
- For non-critical security hardening, standard PRs are welcome (e.g., improved input validation, additional masking patterns).
- We will credit security contributors in release notes (with permission).

---

## Plugin & Module Contributions

Siyarix supports plugin-style extensions. When contributing a new module:

1. Ensure it follows the existing module patterns in `src/siyarix/`.
2. Register any new providers in the appropriate registry.
3. Add tests in `tests/` following existing test patterns.
4. Document the module's purpose, configuration, and usage.
5. If your module has external dependencies, add them to the appropriate optional dependency group in `pyproject.toml`.

---

## Documentation Contributions

Documentation improvements are always welcome:

- Fix typos and clarify unclear sections.
- Add examples for under-documented features.
- Keep documentation consistent with current behavior.
- If you change CLI behavior or slash commands, update the corresponding docs.

---

## AI-Generated Code Disclosure

We welcome contributions regardless of how they are authored, including with AI assistance. However:

- You are responsible for any code you submit, regardless of how it was generated.
- Disclose AI assistance in your PR description if the majority of the contribution was AI-generated.
- AI-generated code must still follow all project coding standards and include appropriate tests.
- The project maintainers reserve the right to request modifications to AI-generated contributions.

---

## Community & Communication

- **GitHub Issues** — Bug reports, feature requests, discussions
- **GitHub Discussions** — General questions, ideas, community support
- **Pull Requests** — Code contributions

We strive to be responsive and kind. There are no stupid questions.

---

## Licensing

By contributing to Siyarix, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (SPDX: `AGPL-3.0-or-later`). You must have the right to license your contributions under these terms.

---

*Happy hacking, and thank you for helping make Siyarix better.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
