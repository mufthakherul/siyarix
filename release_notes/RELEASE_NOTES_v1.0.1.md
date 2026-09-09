# Siyarix v1.0.1 — Quality & Security Hardening

**Release Date:** June 30, 2026
**Version:** 1.0.1
**License:** AGPL-3.0-or-later
**Author:** MD MUFTHAKHERUL ISLAM MIRAZ

---

## Overview

Siyarix v1.0.1 is a maintenance and security hardening release focused on resolving initial feedback, fixing bugs across package installations, securing our CI/CD pipelines, and refining the user experience in the interactive terminal. This release includes several key enhancements for local developer workflows and ensures robust execution in restricted runtime environments like Android Termux and locked-down CI pipelines.

---

## What's New in v1.0.1

### 🛠️ CLI, REPL & Installer Enhancements

- **Real-Time Provider Statuses:** The LLM Status panel in the interactive REPL now displays each provider's status on its own line for cleaner rendering and instant diagnostics.
- **Live Health Diagnostics:** Added support for live local provider checks in status gathering.
- **Configurable Diagnostics:** The health check timeout is now fully configurable via settings (via `provider_utils` updates).
- **Installer Restructuring:** Relocated all main installer scripts (`install.sh`, `install.ps1`, `install-termux.sh`) into a dedicated `installer/` directory. Added automated Python bootstrapping, robust virtual environment setups, and cleaned environment PATH resolution.
- **Simplified Setup:** Removed post-installation diagnostic blocks and checks from all installers to ensure a clean, distraction-free installation experience.

### 📦 Automated Package Manager Releases

- **Chocolatey Support:** Added a `publish-chocolatey` release job that packages the application (`nuget pack`) and pushes the `.nupkg` directly to Chocolatey.
- **Homebrew Automation:** Configured automatic custom Homebrew tap formula updates. The release workflow now clones the tap repository, updates the `siyarix.rb` formula, and commits/pushes it directly.

### 🐛 Bug Fixes & System Stability

- **PowerShell Session Fixes:** Resolved an issue where the Windows installer (`install.ps1`) would close the powershell console automatically on completion.
- **Termux Installer Enhancements:** Bundled precompiled python dependencies in the Termux installer to bypass local build failures for packages without pre-built wheels (like `cryptography`).
- **Encoding Issues:** Fixed encoding issues in session exports and integrated audit logs on systems running Windows with non-UTF-8 local encoding.
- **Type Checker Cleanups:** Resolved mypy type checking warnings in `Prompt.ask`, session exports, and other CLI components.

### 🛡️ Security & CI/CD Hardening

- **CodeQL Security Updates:** Addressed and resolved CodeQL static analysis alerts in `tool_handlers.py`, `threat_intel.py`, and `webhooks.py` by ensuring proper resource context manager practices and safe exception handling.
- **OpenSSF Scorecard Tuning:**
  - Pinned all workflow actions and dependency builds to secure commit SHA hashes to satisfy OpenSSF Scorecard rules.
  - Restricted GITHUB_TOKEN permissions across all workflow definitions.
  - Disabled SARIF uploads of Scorecard results to the repository's Code Scanning alerts page to reduce alert noise and focus on direct vulnerabilities.
- **Pipeline Failures:** Resolved version validation issues, TestPyPI publishing configurations, and auto-merge workflow errors.
