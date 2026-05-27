# Security Policy

**Effective Date:** May 2026
**Version:** 1.0.0

Siyarix is a cybersecurity platform that handles security-sensitive operations, API credentials, and target information. We take the security of the platform itself seriously and encourage responsible disclosure of vulnerabilities.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (latest) | ✅ Active development — security patches provided |
| < 0.1 | ❌ No longer supported |

Only the latest minor release receives security patches. Users are encouraged to always run the most recent version.

---

## Reporting a Vulnerability

### Private Reporting Process

If you discover a security vulnerability in Siyarix, **do not** open a public GitHub issue. Instead:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to: `https://github.com/mufthakherul/phalanx/security/advisories`
   - Click "New advisory" and fill out the form
   - Provide sufficient detail for reproduction

2. **Email** (Alternative)
   - Send details to the security contact (see maintainer profile on GitHub)
   - Encrypt sensitive information using the maintainer's GPG key if available

### What to Include

- Type of vulnerability (XSS, command injection, credential exposure, etc.)
- Full steps to reproduce
- Affected component(s) and version(s)
- Proof of concept or demonstration (if possible)
- Your contact information for follow-up

### Scope

In-scope for security reports:
- Privilege escalation within the platform
- Credential vault weaknesses
- Safety resolver bypass
- Unauthorized command execution
- Data masking failures
- Authentication/authorization issues
- Remote code execution

Out-of-scope:
- Dependency CVEs already publicly known and tracked
- Theoretical attacks requiring physical access or advanced persistent threat capabilities
- UI/UX issues that do not affect security

---

## Disclosure & Embargo

- We will acknowledge receipt within **72 hours**.
- We aim to triage and begin work on a fix within **5 business days**.
- We request a **90-day embargo** from initial report to public disclosure, to allow time for patches and coordinated release.
- We will coordinate with you on the disclosure timeline and credit.
- If a fix cannot be produced within 90 days, we will negotiate an extended timeline transparently.

---

## Severity Classification

| Severity | Response Time | Fix Target | Notification |
|----------|---------------|------------|--------------|
| 🔴 Critical | < 24h acknowledgment | 7 days | Security advisory + release notes |
| 🟠 High | < 48h acknowledgment | 14 days | Security advisory + release notes |
| 🟡 Medium | < 72h acknowledgment | 30 days | Release notes |
| 🟢 Low | < 1 week acknowledgment | Next release | Release notes |

---

## CVE Coordination

We are prepared to coordinate CVE assignments for confirmed vulnerabilities through GitHub Security Advisories and/or MITRE. Reporters may request CVE credit.

---

## Safe Harbor

When conducting security research on Siyarix in accordance with this policy:

- We will not pursue legal action against researchers who follow this disclosure process.
- We will not threaten DMCA or similar claims for good-faith security research.
- We consider security research conducted under this policy as authorized use.

**However, this safe harbor does not extend to:**
- Research that causes harm to users, systems, or data
- Testing against production systems without authorization
- Public disclosure before the embargo period ends
- Exploitation of vulnerabilities beyond what is necessary to demonstrate them

---

## Security Features in Siyarix

Siyarix includes the following built-in security mechanisms:

| Feature | Description |
|---------|-------------|
| **Encrypted Credential Vault** | AES-256-GCM encryption for API keys and secrets |
| **Safety Resolver** | Heuristic command safety checks before execution |
| **Data Masking Engine** | Bidirectional masking of sensitive data sent to AI providers |
| **Permission Gates** | User approval required for high-risk operations |
| **Kill Switch** | Emergency stop for running operations |
| **Audit Logging** | Tamper-evident execution records |
| **Input Validation** | Protection against injection and dangerous command patterns |
| **RBAC** | Role-based access control for team deployments |

---

## Dependency Security

- All dependencies are pinned to specific versions in `pyproject.toml`.
- Automated dependency scanning runs via GitHub Actions (`security.yml`).
- `pip-audit` is used in CI to detect known vulnerabilities.
- Critical dependencies (`cryptography`, `httpx`, `defusedxml`, etc.) are monitored for security advisories.

---

## Contact

For security-related inquiries not involving vulnerability disclosure:

- GitHub Issues (for non-security bugs): Standard issue tracker
- Security Advisories: GitHub Security tab on the repository

*We appreciate the security community's help in keeping Siyarix safe for everyone.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
