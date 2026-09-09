# 📊 OpenSSF Scorecard Integration

Siyarix integrates **OpenSSF Scorecard** (Open Source Security Foundation) to automatically analyze and evaluate the project's security posture, supply chain security, and development best practices.

---

## 🌟 Overview

The OpenSSF Scorecard assesses the project against a series of automated checks, helping us identify and remediate potential security risks in the codebase, build pipelines, and dependencies.

Our OpenSSF Scorecard status is publicly visible via the scorecard badge in our `README.md`.

---

## ⚙️ Core Security Controls & Checks

We actively maintain a high scorecard rating by strictly implementing the following supply-chain and development practices:

### 1. Token Permissions (Least Privilege)
- **Status:** Enforced
- **Implementation:** All GitHub Actions workflows (`.github/workflows/*.yml`) explicitly define restricted token permissions. The default permission level is set to `read-all` or `contents: read` at the top level. Higher-level write permissions (like `security-events: write` or `id-token: write`) are only granted to specific jobs that require them (e.g. publishing packages or uploading scan results).

### 2. Pinned Action & Build Dependencies
- **Status:** Enforced
- **Implementation:**
  - **Workflows:** All external GitHub Actions are pinned to precise git commit SHA hashes instead of mutable version tags (e.g. `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5` rather than `@v4`).
  - **Docker Build:** The project `Dockerfile` uses specific base image SHAs and tags, pinning dependency versions where possible to prevent unverified upstream supply-chain injection.

### 3. Vulnerability Scanning
- **Status:** Automated
- **Implementation:**
  - Automated weekly dependency vulnerability scans run via `pip-audit` to detect known CVEs in our dependency tree.
  - Container vulnerability scans run via `trivy` on built Docker images.
  - Code analysis runs via `CodeQL` to identify common coding vulnerabilities (CWEs) and security hotspots.

### 4. Cryptographic Chaining & Integrity
- **Status:** Enforced
- **Implementation:** Siyarix maintains a cryptographically chained, tamper-evident audit trail for all sessions to prevent local log tampering.

---

## 🏃 Running Scorecard Checks

We run the Scorecard analysis automatically through two pipelines:

1. **Weekly Supply Chain Check:** A dedicated workflow (`.github/workflows/scorecards.yml`) runs every Saturday at 01:30 UTC to perform a complete repository check.
2. **Commit Pipeline Check:** The main security workflow (`.github/workflows/security.yml`) executes a scorecard check on every push to the `main` branch.

### Verification Command

You can run scorecard checks locally using the `scorecard` CLI tool (if installed):

```bash
scorecard --repo=github.com/mufthakherul/siyarix
```
