!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 📋 Compliance Frameworks

Navigating compliance audits can be overwhelming, but Siyarix is here to help simplify the process. We are actively building out automated probes and evidence collection to assess your systems against six major industry compliance frameworks!

!!! warning
    **Active Development Notice**: The compliance assessment engine is currently a work in progress! At the moment, running compliance checks will return a `NOT_EVALUATED` status because we are carefully building out the underlying evaluation logic.

---

## 🏛️ Supported Frameworks

Once fully implemented, Siyarix will help you assess your posture against:

| Framework | Full Name | Planned Controls |
|-----------|-----------|------------------|
| **PCI-DSS** | Payment Card Industry Data Security Standard | 3 |
| **ISO 27001** | Information Security Management Standard | 3 |
| **NIST 800-53** | Security and Privacy Controls | 3 |
| **SOC 2** | Service Organization Control 2 | 3 |
| **GDPR** | General Data Protection Regulation | 2 |
| **HIPAA** | Health Insurance Portability and Accountability Act | 2 |

---

## 🏃 Running Compliance Checks

It's designed to be incredibly simple to run a check against any target:

```bash
# Check a specific framework against your target infrastructure
siyarix compliance run SOC2 10.0.0.1
siyarix compliance run PCI-DSS webapp.example.com
siyarix compliance run GDPR customer-db.internal
```

!!! note
    The `compliance run` command requires two things: the **Framework Name** and the **Target**.

### Current Engine Status
Right now, calling `ComplianceCheck.run()` acts as a placeholder and returns `NOT_EVALUATED`. Behind the scenes, we are actively writing the assessment probes and evidence collection modules. Currently, evidence data and target metadata *are* being captured and stored for future evaluation.

---

## 🔎 Control Examples by Framework

Here is a sneak peek at the types of controls Siyarix will automatically verify for you:

### 💳 PCI-DSS
| Control ID | What We Check For |
|-----------|-------------------|
| **Req-1.1** | Strict firewall configuration standards |
| **Req-6.1** | Robust security patching processes |
| **Req-10.1** | Comprehensive audit trail implementation |

### 🏢 SOC 2
| Control ID | What We Check For |
|-----------|-------------------|
| **cc1.1** | Sound control environment practices |
| **cc6.1** | Logical and physical access restrictions |
| **cc6.2** | Secure access provisioning and deprovisioning |

### 🌍 GDPR
| Control ID | What We Check For |
|-----------|-------------------|
| **Art. 32** | Overall security of processing |
| **Art. 33** | Proper breach notification mechanisms |

---

## 🕵️ Automated Evidence Collection

Audits require proof! Siyarix doesn't just say "pass" or "fail"; it collects the receipts. Our automated probes gather structured evidence for your auditors, including:

- **Tool Detection**: Proving required security tools (like AV or EDR) are actively running.
- **Process Verification**: Ensuring logging, monitoring, and response mechanisms are configured.
- **Configuration Checks**: Verifying encryption standards, access controls, and audit settings.
- **Documentation Scans**: Checking if required policy and procedure documents actually exist.

---

## 📄 Understanding the Output

Every control we assess provides clear, structured feedback:

| Field | What It Means |
|-------|---------------|
| `check_id` | The specific identifier for the framework (e.g., cc1.1) |
| `status` | Did you pass? (Currently defaults to `NOT_EVALUATED`) |
| `evidence_data` | The hard proof we collected to support the status |
| `message` | A human-readable description of what we found |

### Example Output
```json
{
  "framework": "SOC2",
  "target": "10.0.0.1",
  "results": [
    {
      "check_id": "cc1.1",
      "status": "NOT_EVALUATED",
      "message": "Stub check — not yet evaluated against live controls."
    }
  ]
}
```

---

## 📊 Report Generation

When audit time comes, you need beautiful, easy-to-read reports. Siyarix makes it a breeze!

```bash
# 📄 Generate a stunning HTML compliance report
siyarix report generate --format html --output compliance-report.html

# 💻 Export raw JSON data for your CI/CD pipelines
siyarix report generate --format json
```
