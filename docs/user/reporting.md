# 📊 Reporting and Output

Data is only useful if you can understand it. Siyarix provides incredibly flexible output formats, comprehensive report generation, tamper-evident audit logging, and detailed system health metrics.

---

## 📝 Output Formats

Want data presented your way? Set your preferred default format easily:

```bash
siyarix config set default_output_format json
```

Siyarix supports a wide variety of formats for different use cases:

| Format | What It's Good For |
|--------|--------------------|
| **TABLE** | Beautiful, human-readable terminal output *(Default)* |
| **JSON** | Machine-readable data for scripting and integrations |
| **JSONL** | JSON Lines, perfect for streaming large datasets |
| **YAML** | Clean, structured data |
| **CSV** | Importing into Excel or databases |
| **HTML** | Sharing findings with non-technical stakeholders |
| **XML** | Legacy system integrations |
| **MARKDOWN**| Dropping directly into Jira or GitHub issues |
| **RAW** | The unadulterated tool output |
| **QUIET** | Silence! Only show critical errors |

!!! tip
    You can always override the default format on the fly using the `--output` flag (e.g., `siyarix scan --output html`).

---

## 📄 Report Generation

Need to hand something to your boss or a client? Generate a comprehensive report instantly:

```bash
siyarix report generate --format html --output report.html
```

### Supported Report Formats

| Format | Best Used For |
|--------|---------------|
| **HTML** | Client-ready, styled reports with charts and graphs. |
| **JSON** | Pushing results directly into CI/CD pipelines or SIEMs. |
| **Markdown**| Quick documentation or team wikis. |
| **SARIF** | Integrating with standard static analysis tools (like GitHub Advanced Security). |

### What's Inside the Report?

A standard Siyarix report includes:
- **Executive Summary**: The "too long; didn't read" overview of your security posture.
- **Methodology**: Exactly how the scan was performed and what tools were used.
- **Findings**: Deep dives into vulnerabilities, ranked by severity.
- **Evidence**: The raw proof (command outputs, intercepted data).
- **Remediation**: Step-by-step instructions on how to fix the problems!
- **Appendix**: Extra technical details for the engineering team.

---

## 🔒 Audit Logging

Trust, but verify. Every single action taken in Siyarix is logged to an capable, tamper-evident audit trail.

```bash
# 📄 Export logs for compliance (like SOC 2)
siyarix audit report soc2 -o audit-report.md

# 📜 View the raw audit logs
siyarix audit logs

# ✅ Verify the logs haven't been tampered with
siyarix audit verify
```

### Audit System Features
- **Tamper Evidence**: Siyarix uses a cryptographic SHA-256 hash chain. If a log file is manually edited, Siyarix will know!
- **Session Tracking**: Every command is tied to a specific session ID.
- **Export Options**: Export logs to JSON or CSV for your SIEM.
- **Advanced Filtering**: Filter logs by event type, user, severity, or specific date ranges.

---

## 📈 System Metrics

Curious about how much work Siyarix is doing?

```bash
siyarix metrics
```

The metrics dashboard gives you performance statistics at a glance:
- Total number of scans performed
- Success vs. failure rates
- Average duration of your scans
- Total vulnerabilities found
- How many AI plans were generated
- Total AI model calls and API errors

*Supports `--output table|json|prometheus` for seamless monitoring integration!*

---

## 🩺 Health Check

Is everything running smoothly? Run a quick diagnostic check:

```bash
siyarix health
```

This generates a comprehensive system report covering:
- **Component Status**: Are Python, core modules, and AI providers functioning?
- **Platform Info**: OS details, shell type, and Python version.
- **System State**: Is Siyarix properly initialized and configured?
- **Storage**: How much disk space are your offline databases using?
- **Network**: Can Siyarix reach your configured AI providers?
- **Tool Check**: Are your essential security tools (Nmap, Nikto, etc.) actually installed and on your PATH?
