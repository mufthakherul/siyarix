!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 🏗️ Infrastructure as Code (IaC) Scanning

Catch security flaws before they ever reach production! Infrastructure as Code (IaC) scanning allows you to analyze your configuration files for vulnerabilities, misconfigurations, and exposed secrets early in the development lifecycle.

!!! warning
    **Active Development Notice**: Siyarix's IaC scanning capability is currently under active development. An `IaCScanner` stub is in place, and we are actively building out the engines for Terraform, CloudFormation, Helm, and Dockerfiles.

---

## 🚧 Current Status

Currently, the `IaCScanner` class exists as a stub. You can interact with it, but it does not yet perform actual AST parsing or pattern matching.

```python
from siyarix.chat.stubs import IaCScanner

scanner = IaCScanner()

# This is a stub! It currently returns an empty dictionary {}.
result = scanner.scan_path("infrastructure/terraform")
```

---

## 🔮 Planned Capabilities

We are building a comprehensive IaC scanner. Here is what is on the roadmap:

| Format | What We Will Analyze |
|--------|----------------------|
| **Terraform** | Deep HCL analysis of `.tf` and `.tfvars` files. |
| **CloudFormation** | Resource configuration checks in `.yaml` and `.json`. |
| **Helm** | Kubernetes security checks inside `values.yaml` and templates. |
| **Dockerfile** | Container build best practices and security validations. |
| **Generic Secrets** | Aggressive, pattern-based secret detection across *all* files. |

### 🕵️ What We Will Detect

Once fully operational, the scanner will automatically hunt down:

- **Misconfigurations**: Publicly exposed S3 buckets, wide-open security groups, and overly permissive IAM roles.
- **Exposed Secrets**: Hardcoded API keys, database passwords, access tokens, and private keys left in your code.
- **Compliance Violations**: Resources deployed with encryption disabled, logging turned off, or insecure default settings.
- **Supply Chain Risks**: Identifying unpinned container tags or the use of risky, unofficial base images.

---

## 🔄 CI/CD Integration (Planned)

Security should be automated! We are designing the IaC scanner to integrate seamlessly into your pipelines.

```bash
# 🗣️ Future natural language support:
siyarix run "scan IaC templates for security issues"

# 🛑 Future CI/CD blocking gate:
siyarix ci-gate
```

!!! tip
    The `siyarix ci-gate` command will allow you to automatically fail your build pipeline if critical security issues are found in your infrastructure code!

---

## 📣 Stay Tuned!

The IaC scanner is one of our top priorities. We are actively writing the parsing engines and will provide updates on supported formats and release timelines as development progresses.
