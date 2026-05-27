# Compliance Frameworks

Siyarix can assess targets against 6 industry compliance frameworks.

## Supported frameworks

| Framework | Full name | Controls |
|-----------|-----------|----------|
| PCI-DSS | Payment Card Industry Data Security Standard | 4 |
| ISO 27001 | Information Security Management Standard | 4 |
| NIST 800-53 | Security and Privacy Controls | 4 |
| SOC 2 | Service Organization Control 2 | 4 |
| GDPR | General Data Protection Regulation | 4 |
| HIPAA | Health Insurance Portability and Accountability Act | 2 |

## Running compliance checks

```bash
# Check all frameworks
siyarix run "check compliance on the infrastructure"

# Check a specific framework
siyarix run "run SOC 2 compliance scan"

# Via the CLI command
siyarix security compliance --framework soc-2
```

## Control examples by framework

### PCI-DSS

| Control ID | Title | What is checked |
|-----------|-------|-----------------|
| PCI-6.5 | Address common coding vulnerabilities | Security tools present for SAST/DAST |
| PCI-7.1 | Restrict access to need-to-know | IAM/logging processes verified |
| PCI-8.1 | Unique user IDs | Auth mechanisms in place |
| PCI-10.1 | Audit trails | Audit logging confirmed active |

### SOC 2

| Control ID | Title | What is checked |
|-----------|-------|-----------------|
| SOC-CC1 | Control Environment | Governance processes detected |
| SOC-CC3 | Risk Assessment | Risk assessment tools found |
| SOC-CC6 | Logical and Physical Access | Access controls verified |
| SOC-CC7 | System Operations | Monitoring and response tools |

### GDPR

| Control ID | Title | What is checked |
|-----------|-------|-----------------|
| GDPR-5 | Lawful Processing | Consent mechanisms verified |
| GDPR-17 | Right to Erasure | Data deletion processes exist |
| GDPR-32 | Security of Processing | Encryption and security tools in place |
| GDPR-33 | Breach Notification | Incident response plan confirmed |

## Output

Results include for each control:

- **Control ID**: Framework-specific identifier
- **Title**: Human-readable name
- **Description**: What the control requires
- **Compliant**: PASS/FAIL
- **Evidence**: Supporting information
- **Remediation**: Steps to achieve compliance
- **Applicable**: Whether the control applies to the target

### Example output

```json
{
  "framework": "soc-2",
  "controls": [
    {
      "control_id": "SOC-CC6",
      "title": "Logical and Physical Access",
      "compliant": true,
      "evidence": "Access control mechanisms detected",
      "severity": "high"
    }
  ]
}
```

## Automated evidence collection

Each compliance check runs automated probes to gather evidence:

- **Tool detection**: Required security tools present on systems
- **Process verification**: Logging, monitoring, and response processes
- **Configuration checks**: Encryption, access controls, audit settings
- **Documentation scan**: Policy and procedure documents present

## Report generation

```bash
# Generate compliance report
siyarix report generate --format html --include compliance
```
