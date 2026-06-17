# 🛡️ Security Policy

**Effective Date:** May 2026  
**Version:** 3.0.0

Siyarix is built by security professionals, for security professionals. Because we handle sensitive operations, API credentials, and target data, the security of the platform itself is our highest priority. We deeply value the role of the security community in keeping Siyarix safe and robust.

---

## 🏗️ Supported Versions

We actively provide security patches for the following versions:

| Version | Status | Security Patches |
|---------|--------|------------------|
| **v3.0.x (Latest)** | ✅ Stable | Active & High Priority |
| **< v3.0** | ❌ EOL | None — Please upgrade immediately |

We recommend always running the latest minor release to ensure you have the most up-to-date security features and patches.

---

## 🚨 Reporting a Vulnerability

### Our Private Disclosure Process
If you discover a security vulnerability, **please do not open a public GitHub issue.** We want to fix it before it can be exploited.

1. **GitHub Security Advisories** (Preferred) 🌟
   - Head over to: `https://github.com/mufthakherul/siyarix/security/advisories`
   - Click "New advisory" and fill out the details.
   - This is the safest and most efficient way to coordinate with us.

2. **Private Email** (Alternative)
   - Send details to the security contact listed on the maintainer's GitHub profile.
   - We highly recommend using GPG encryption for sensitive details.

### What to Include
The more detail you provide, the faster we can fix it! Please include:
- **Type of vulnerability** (e.g., Command Injection, Credential Leak, RCE).
- **Clear steps to reproduce** the issue.
- **Affected component(s)** and version(s).
- **Impact assessment**: What could an attacker achieve?
- **Proof of Concept (PoC)**: If you have one, it helps immensely.

---

## 🎯 Scope

### What We Care About (In-Scope)
- Privilege escalation within the Siyarix environment.
- Weaknesses in the **Credential Vault**.
- Bypassing the **Safety Resolver** or Permission Gates.
- Failures in the **Data Masking Engine**.
- Unauthorized command execution or remote code execution (RCE).

### What We Track Elsewhere (Out-of-Scope)
- Publicly known CVEs in upstream dependencies (these are handled by our automated CI/CD).
- Theoretical attacks requiring physical access to the machine.
- UI/UX bugs that don't have a direct security impact.

---

## 🤝 Our Commitment to You

- **Acknowledgment**: We will acknowledge your report within **48–72 hours**.
- **Triage**: We aim to begin working on a fix within **5 business days**.
- **Embargo**: We request a **90-day embargo** from the report date before public disclosure. This gives our users time to patch.
- **Coordination**: We will coordinate the disclosure timeline with you and ensure you are properly credited.
- **CVEs**: We coordinate CVE assignments through GitHub Security Advisories and MITRE.

---

## 🛡️ Built-in Security Features

Siyarix is hardened by design. Here are some of the layers protecting you:

| Feature | How it Protects You |
|---------|---------------------|
| **Encrypted Vault** | All API keys are stored using **AES-256-GCM** encryption. |
| **Safety Resolver** | A two-stage gate that analyzes every command for danger before execution. |
| **Masking Engine** | Automatically redacts sensitive data (tokens, IPs) before sending them to AI providers. |
| **Audit Trails** | Every single action is logged in a tamper-evident, cryptographically chained trail. |
| **Kill Switch** | Instantly stop all running operations if something goes wrong. |
| **Plugin Sandbox** | Plugins are loaded from a dedicated, restricted user directory. |

---

## 🕊️ Safe Harbor

We want to encourage good-faith security research. If you follow this policy:
- We will **not** pursue legal action against you.
- We consider your research **authorized** under the CFAA and similar laws.
- We will work with you to understand and resolve the issue quickly.

---

*Thank you for helping us keep Siyarix secure. Together, we can build a safer ecosystem for everyone. 🛡️*
