# Security Workflows

This guide covers real-world security workflows using Siyarix commands.

## Network reconnaissance

```bash
# Quick port scan
siyarix scan quick 10.0.0.0/24

# Comprehensive scan with service detection
siyarix scan full target.example.com

# Asset discovery
siyarix discover example.com
```

## Vulnerability assessment

```bash
# Natural language approach
siyarix run "scan target.example.com for common vulnerabilities"

# Multi-tool scan
siyarix scan --all 10.0.0.1

# Workflow-driven assessment
siyarix workflow run assessment.yml
```

## Exploitation chains

```bash
# Multi-phase campaign
siyarix exploit chain "recon -> scan -> enumerate -> exploit -> exfil"

# The exploitation system supports:
#   - Phase sequencing (recon, scan, enumerate, exploit, post, exfil)
#   - Dependency resolution between phases
#   - Conditional execution based on findings
```

## Incident response

```bash
# Launch security dashboard
siyarix security dashboard

# View active incidents
siyarix security incidents

# Run incident response playbook
siyarix security playbooks run containment-playbook
```

## Threat hunting

```bash
# AI-assisted threat hunting
siyarix security hunt "find indicators of compromise in the network"

# MITRE ATT&CK mapping
siyarix security mitre --technique T1078
# Shows tools and commands that map to "Valid Accounts"
```

## Compliance checks

```bash
# Run SOC 2 compliance checks
siyarix run "check SOC 2 compliance on the infrastructure"

# The compliance engine supports:
#   - SOC 2, ISO 27001, NIST frameworks
#   - Control-by-control validation
#   - Automated evidence collection
#   - Pass/fail reporting with remediation suggestions
```

## Cloud security

```bash
# Scan cloud infrastructure
siyarix scan --cloud aws
siyarix scan --cloud azure
siyarix scan --cloud gcp

# Scans for:
#   - Open S3 buckets
#   - Overly permissive security groups
#   - Unencrypted storage
#   - Publicly accessible resources
```

## Web application testing

```bash
# Web vulnerability scanning
siyarix run "scan web application at https://target.com for OWASP Top 10"

# This invokes tools like:
#   - nikto for web server scanning
#   - nuclei for template-based scanning
#   - wpscan for WordPress-specific issues
#   - zaproxy for passive/active scanning
```

## IoT security

```bash
# IoT device scanning
siyarix run "scan IoT devices on the local network"

# Capabilities:
#   - Serial port enumeration
#   - Firmware analysis
#   - Default credential checking
#   - Protocol fuzzing
```

## Infrastructure as Code (IaC) scanning

```bash
# Scan Terraform, CloudFormation, K8s manifests
siyarix run "scan IaC templates for security issues"
```

## Using the agent for goal-driven operations

```bash
# Autonomous agent decomposes objectives
siyarix agent "enumerate all services, find vulnerabilities, and generate a report"

# The agent:
#   1. Decomposes the goal into sub-tasks
#   2. Assigns tasks to specialized sub-agents
#   3. Executes in dependency order
#   4. Aggregates results into a final report
```

## Session logging

All workflow steps are logged with SHA-256 chaining for tamper evidence:

```bash
# View current session log
siyarix session-log

# Session logs include:
#   - Every command executed (with arguments)
#   - Tool outputs (truncated)
#   - Safety events (permission gates triggered, dangerous commands flagged)
#   - Timestamps and durations
```

## Report generation

```bash
# Generate an HTML report of all findings
siyarix report generate --format html

# Supported formats: html, pdf, json, markdown
```
