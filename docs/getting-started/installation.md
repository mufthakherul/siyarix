# Installation Guide

Siyarix v1.0.0 requires **Python 3.11 or later** and supports Linux, macOS, Windows (PowerShell 5.1+), Android (Termux), iOS (iSH), and HarmonyOS. Minimum 512 MB RAM (4 GB+ recommended for AI operations), ~500 MB disk for tool dependencies.

## PyPI (Recommended)

```bash
pip install siyarix
```

### Optional Extras

| Extra | Provides |
|-------|----------|
| `terminal` | Rich, prompt_toolkit, Textual, pywin32 |
| `cli` | Typer, Rich, prompt_toolkit, Textual |
| `siem` | httpx |
| `autonomous` | Anthropic + Google Generative AI + OpenAI SDKs |
| `openai` | OpenAI SDK |
| `gemini` | Google Generative AI SDK |
| `api` | FastAPI + Uvicorn + PyJWT |
| `anthropic` | Anthropic SDK |
| `security` | Bandit, Safety, pip-audit |
| `mobile` | Terminal extra + httpx |
| `windows` | Terminal extra + pywin32 + colorama |
| `all` | All extras combined |
| `dev` | Pytest, ruff, mypy, pre-commit, build, twine |

```bash
pip install "siyarix[openai,gemini,anthropic]"
pip install "siyarix[autonomous]"
pip install "siyarix[all]"
pip install "siyarix[dev]"
```

## Package Managers

**macOS (Homebrew)**
```bash
brew install --build-from-source packages/homebrew/siyarix.rb
```

**Windows (Winget)**
```bash
winget install Mufthakherul.Siyarix
```

**Windows (Chocolatey)**
```bash
choco install siyarix
```

**Debian/Ubuntu/Kali**
```bash
sudo dpkg -i packages/deb/siyarix_1.0.0-1_all.deb
```

**Docker**
```bash
docker pull siyarix:latest
docker run siyarix:latest --help
```

## Build from Source

```bash
git clone https://github.com/mufthakherul/siyarix.git
cd siyarix
python -m venv .venv
# source .venv/bin/activate  (Linux/macOS)
# .\.venv\Scripts\Activate.ps1  (Windows)
pip install -e ".[all,cli,siem]"
```

## Platform Install Scripts

Siyarix provides platform-specific installers for automated setup:

```bash
# Linux/macOS
curl -fsSL https://siyarix.dev/install.sh | bash

# Windows (PowerShell)
irm https://siyarix.dev/install.ps1 | iex

# Android (Termux)
bash install_android.sh

# HarmonyOS
bash install_harmonyos.sh

# iOS (iSH)
bash install_ios.sh
```

## Verify Installation

```bash
siyarix --version
siyarix --help
```

## Next Steps

- [Onboarding Wizard](onboarding.md) — Interactive 11-step setup
- [Setup & Configuration](setup.md) — API keys, credentials, settings
- [First Run](first-run.md) — Your first session
