> [!NOTE]
> 👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# ☁️ Cloud Security Scanning

Securing your cloud environments doesn't have to be a headache. Siyarix comes packed with multi-cloud security scanning capabilities right out of the box, covering AWS, Azure, GCP, Kubernetes, and Docker. 

> [!NOTE]
> Siyarix is smart! It only queries a provider's SDK if it detects that the respective cloud credentials are available on your system.

---

## 🏢 Supported Providers

Here is a quick look at the platforms we currently support and what you need to get started:

| Provider | Number of Checks | What You Need |
|----------|------------------|---------------|
| **AWS** | 5 | `boto3` installed, AWS credentials configured |
| **Azure** | 3 | `azure-identity` installed, Azure credentials |
| **GCP** | 3 | `google-cloud-resource-manager` installed, GCP credentials |
| **Kubernetes** | 3 | `kubernetes` Python package, valid `kubeconfig` |
| **Docker** | 3 | `docker` Python package, running Docker daemon |

---

## 🔍 How to Scan

Starting a scan is incredibly simple. You can scan everything at once, target specific providers, or just use natural language!

```bash
# 🌍 Scan ALL configured cloud providers
siyarix scan --cloud all

# 🎯 Target specific providers
siyarix scan --cloud aws
siyarix scan --cloud azure
siyarix scan --cloud gcp
siyarix scan --cloud kubernetes
siyarix scan --cloud docker

# 🗣️ Use natural language!
siyarix run "check AWS for security misconfigurations"
```

---

## 📋 Security Checks by Provider

Curious about what we're looking for? Here are the specific misconfigurations Siyarix hunts down:

### 🟠 AWS Checks
| Check ID | What We Look For | Severity |
|----------|------------------|----------|
| `S3_PUBLIC_ACCESS` | Are your S3 buckets wide open to the public? | **HIGH** |
| `IAM_OVERLY_PERMISSIVE` | Do your IAM policies grant `*:*` (everything to everyone)? | **CRITICAL** |
| `SECURITY_GROUP_OPEN` | Are security groups allowing SSH from anywhere (`0.0.0.0/0`)? | **HIGH** |
| `UNENCRYPTED_EBS` | Are your EBS volumes missing encryption? | **MEDIUM** |
| `CLOUDTRAIL_DISABLED` | Is AWS CloudTrail turned off? (You need those logs!) | **HIGH** |

### 🔵 Azure Checks
| Check ID | What We Look For | Severity |
|----------|------------------|----------|
| `NSG_OPEN` | Do Network Security Groups allow RDP/SSH from any source? | **HIGH** |
| `BLOB_PUBLIC_ACCESS` | Can anyone access your Blob storage containers anonymously? | **HIGH** |
| `RBAC_OVERPRIVILEGED` | Are RBAC role assignments giving away too much power? | **MEDIUM** |

### 🟢 GCP Checks
| Check ID | What We Look For | Severity |
|----------|------------------|----------|
| `BUCKET_PUBLIC_ACCESS` | Are GCS buckets publicly accessible? | **HIGH** |
| `FIREWALL_OPEN` | Do firewall rules allow `0.0.0.0/0` on management ports? | **HIGH** |
| `IAM_PRIMITIVE_ROLE` | Are primitive roles (owner/editor/viewer) actively assigned? | **MEDIUM** |

### ☸️ Kubernetes Checks
| Check ID | What We Look For | Severity |
|----------|------------------|----------|
| `POD_ROOT_USER` | Are your containers running as root? | **HIGH** |
| `PRIVILEGE_ESCALATION` | Is privilege escalation allowed on pods? | **HIGH** |
| `HOST_NETWORK` | Are pods tying into the host network namespace? | **MEDIUM** |

### 🐳 Docker Checks
| Check ID | What We Look For | Severity |
|----------|------------------|----------|
| `ROOT_USER` | Are your Docker containers running as root? | **HIGH** |
| `SENSITIVE_ENV` | Do environment variables expose sensitive secrets? | **MEDIUM** |
| `NO_HEALTHCHECK` | Are containers missing standard health checks? | **LOW** |

---

## 🔑 Credential Configuration

You don't need to jump through hoops to configure credentials. Siyarix automatically looks for them in this order:

1. **Environment Variables**: Like `AWS_ACCESS_KEY_ID`, `AZURE_CLIENT_ID`, etc.
2. **Default Chains**: Standard locations (like `~/.aws/credentials`).
3. **Siyarix Store**: Credentials saved via `siyarix auth set-key <provider>`.

---

## 📈 Understanding the Output

When a scan finishes, you'll get detailed results including the Check ID, Severity, Description, and most importantly: **Remediation Guidance** (how to fix it!).

> [!TIP]
> Need to pipe the output to another tool? Use the `--output` flag for clean JSON!
> ```bash
> siyarix scan --cloud aws --output json
> ```

---

## 🚀 What's Next? (Planned Enhancements)

We're constantly improving! While our current scanner is great for quick, provider-specific checks, we are actively building a comprehensive `CloudScanner`. 

Future updates will include:
- Deep multi-account support
- Cross-provider correlation (spotting complex attack paths)
- Automated, click-to-fix remediation!
