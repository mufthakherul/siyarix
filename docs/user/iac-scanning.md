# Infrastructure as Code Scanning

Siyarix includes a built-in IaC scanner that checks Terraform, CloudFormation, Helm charts, and Dockerfiles for security misconfigurations.

## Supported formats

| Format | Checks | Files |
|--------|--------|-------|
| Terraform | 15 | `*.tf`, `*.tfvars` |
| CloudFormation | 3 | `*.yaml`, `*.json` |
| Helm | 7 | `values.yaml`, templates |
| Dockerfile | 2 | `Dockerfile` |
| Generic secrets | 9 | All files |

## Usage

```bash
# Scan current directory
siyarix run "scan IaC templates for security issues"

# Scan a specific directory
siyarix run "scan infrastructure/terraform for misconfigurations"
```

## Terraform checks

| Pattern | Issue | Severity |
|---------|-------|----------|
| `s3_bucket.*acl.*public-read` | S3 bucket public-read ACL | HIGH |
| `s3_bucket.*acl.*public-read-write` | S3 bucket public-read-write ACL | CRITICAL |
| `ingress.*cidr_blocks.*["0.0.0.0/0"]` | Security group all inbound traffic | HIGH |
| `iam_role_policy.*Action.*"*"` | IAM wildcard Action | MEDIUM |
| `iam_role_policy.*Resource.*"*"` | IAM wildcard Resource | MEDIUM |
| `password.*true.*false` | Password authentication enabled | MEDIUM |
| `aws_db_instance.*storage_encrypted.*false` | Unencrypted RDS | HIGH |
| `kms_key.*rotation_enabled.*false` | KMS key rotation disabled | LOW |

## Helm checks

| Pattern | Issue | Severity |
|---------|-------|----------|
| `privileged: true` | Privileged container | HIGH |
| `runAsRoot: true` | Container runs as root | HIGH |
| `latest` tag | Container uses `latest` tag (no pin) | MEDIUM |
| `imagePullPolicy: Always` | Unnecessary pull policy | LOW |

## Secret detection

Generic secret patterns checked across all files:

| Pattern | What it detects |
|---------|-----------------|
| `password\s*[:=]` | Plain-text passwords |
| `-----BEGIN.*KEY-----` | Embedded private keys |
| `ghp_[a-zA-Z0-9]{36}` | GitHub tokens |
| `sk-[a-zA-Z0-9]{20,}` | OpenAI API keys |
| `AKIA[0-9A-Z]{16}` | AWS access keys |

## Output format

```json
{
  "findings": [
    {
      "file": "main.tf",
      "line": 42,
      "severity": "high",
      "rule": "S3 bucket public-read ACL",
      "message": "S3 bucket 'logs' has public-read ACL",
      "remediation": "Set acl to private or use bucket policies"
    }
  ],
  "files_scanned": 12,
  "total_lines": 340
}
```

## Integration

IaC scanning can be integrated into CI/CD pipelines:

```bash
# Fail pipeline on high-severity findings
siyarix run "scan IaC templates" --exit-on-findings high
```
