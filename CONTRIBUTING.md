# Contributing to Siyarix 🚀

First off, a massive **thank you** for even considering contributing to Siyarix! Whether you're a seasoned security pro, a Python enthusiast, a student just starting out, or a documentation wizard—your help is what makes Siyarix thrive. 

We aim to make Siyarix the gold standard for AI-native security orchestration, and we can't do that without an amazing community like you.

---

## 🗺️ Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Your Contribution Journey](#your-contribution-journey)
- [Our Coding Standards](#our-coding-standards)
- [Commit Conventions](#commit-conventions)
- [Reporting Issues](#reporting-issues)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Security Contributions](#security-contributions)
- [Plugins & Modules](#plugins--modules)
- [Documentation & AI Disclosure](#documentation--ai-disclosure)

---

## 🤝 Code of Conduct

We are committed to providing a welcoming, safe, and harassment-free environment for everyone. Before you begin, please review our [Code of Conduct](CODE_OF_CONDUCT.md). Kindness and respect are our top priorities.

---

## 🚀 Getting Started

### 📋 Prerequisites
- **Python**: version 3.11 or later.
- **Git**: installed and configured.
- **GitHub Account**: for forking and opening PRs.

### 🛠️ Setting Up Your Environment
```bash
# 1. Fork the repo on GitHub, then clone your fork:
git clone https://github.com/YOUR-USERNAME/siyarix.git
cd siyarix

# 2. Set up a pristine virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .\.venv\Scripts\activate.ps1

# 3. Install Siyarix in editable mode with all dev dependencies
pip install -e ".[all,cli,siem]" pytest ruff mypy
```

### 🧪 Verify Your Setup
Run these commands to make sure everything is humming along perfectly:
```bash
pytest -q           # Run the test suite
ruff check .        # Check for linting issues
mypy src/siyarix/   # Run static type checking
```

---

## 🛣️ Your Contribution Journey

1. **Find an Opportunity**: Browse our [Issues](https://github.com/mufthakherul/siyarix/issues) or start a discussion. If you have a big idea, it's best to discuss it first!
2. **Fork and Branch**: Always work on a fresh branch from `main`:
   ```bash
   git checkout -b feat/my-exciting-new-feature
   ```
3. **Build & Test**: Make your changes. We love clean, well-tested code.
4. **Quality Check**: Run `pytest`, `ruff`, and `mypy` one last time.
5. **Commit**: Use [Conventional Commits](#commit-conventions) and sign off with `-s`.
6. **PR & Review**: Push your branch and open a Pull Request. We’ll be there to review it!

---

## ✨ Our Coding Standards

We keep the Siyarix codebase clean, modern, and high-performance. 

- **Language**: Python 3.11+ using modern async/await patterns.
- **Formatting**: We use [Ruff](https://docs.astral.sh/ruff/) for everything. No need to debate style—just run `ruff format .`.
- **Type Safety**: We love type hints! All public APIs must be fully typed.
- **Documentation**: Use Google or NumPy style docstrings for all public functions.
- **Testing**: If you add a feature, add a test. If you fix a bug, add a regression test.

---

## 💬 Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification to keep our history readable and automated.

Format: `<type>(<scope>): <description>`

| Type | When to use it |
|------|----------------|
| `feat` | Adding a shiny new feature. |
| `fix` | Squashing a bug. |
| `docs` | Improving documentation. |
| `test` | Adding or updating tests. |
| `refactor` | Improving code without changing behavior. |
| `security` | Security hardening or vulnerability fixes. |
| `chore` | Maintenance, dependencies, or tooling. |

**Important**: Please sign off on your commits using `git commit -s`. This confirms your agreement with the Developer Certificate of Origin (DCO).

---

## 🐛 Reporting Issues

### Found a Bug?
Help us squash it! Provide:
- A clear, concise description.
- A minimal, reproducible example.
- Your environment details (OS, Python version, Siyarix version).

### Have a Feature Idea?
We’d love to hear it! Explain the "Why" before the "How." What problem does it solve for security operators?

### Found a Security Vulnerability?
**Stop!** Please do **not** report security issues via public GitHub issues. Check out our [Security Policy](SECURITY.md) for private disclosure instructions.

---

## ✅ Pull Request Guidelines

Before you hit "Submit":
- Does the code pass all tests and linting?
- Have you added tests for your changes?
- Is the documentation updated?
- Is your PR description clear about **what** changed and **why**?

Once submitted, a maintainer will review your work. We strive to be responsive and helpful—don't be afraid of feedback; it's how we all grow!

---

## 🧩 Plugins & Modules

Siyarix is designed to be extensible. If you're contributing a new parser, provider, or tool handler:
1. Follow existing patterns in `src/siyarix/`.
2. Ensure your module is properly registered.
3. Add any new external dependencies to `pyproject.toml` in the correct extra group.

---

## 📄 Documentation & AI Disclosure

### Documentation
Docs are just as important as code. If you find a typo or an unclear section, please fix it!

### AI-Generated Code
We welcome the use of AI tools (like Copilot or ChatGPT) to help you author code! We only ask that:
- You remain responsible for the final code.
- You disclose significant AI assistance in your PR description.
- You ensure the AI-generated code meets our quality and testing standards.

---

## ⚖️ Licensing

By contributing, you agree that your work will be licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (SPDX: `AGPL-3.0-or-later`). 

---

*Thank you for being part of the Siyarix journey. Happy hacking! 🛡️*
