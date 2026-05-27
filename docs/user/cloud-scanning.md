# Cloud Security Scanning

Siyarix includes a built-in multi-cloud security scanner that checks AWS, Azure, GCP, Kubernetes, and Docker configurations.

## Supported providers

| Provider | Checks | Requirements |
|----------|--------|-------------|
| AWS | 5 | `boto3`, AWS credentials configured |
| Azure | 3 | `azure-identity`, Azure credentials |
| GCP | 3 | `google-cloud-resource-manager`, GCP credentials |
| Kubernetes | 3 | `kubernetes` Python package, kubeconfig |
| Docker | 3 | `docker` Python package, Docker daemon |

## Scanning

```bash
# Scan all cloud providers
siyarix scan --cloud all

# Scan a specific provider
siyarix scan --cloud aws
siyarix scan --cloud azure
siyarix scan --cloud gcp
siyarix scan --cloud kubernetes
siyarix scan --cloud docker
```

## AWS checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| S3_PUBLIC_ACCESS | S3 bucket allows public read access | HIGH |
| IAM_OVERLY_PERMISSIVE | IAM policy grants `*:*` to all principals | CRITICAL |
| SECURITY_GROUP_OPEN | Security group allows SSH from 0.0.0.0/0 | HIGH |
| UNENCRYPTED_EBS | EBS volume does not have encryption enabled | MEDIUM |
| CLOUDTRAIL_DISABLED | AWS CloudTrail is not enabled | HIGH |

## Azure checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| NSG_OPEN | Network Security Group allows RDP/SSH from any source | HIGH |
| BLOB_PUBLIC_ACCESS | Blob storage container allows anonymous access | HIGH |
| RBAC_OVERPRIVILEGED | RBAC role assignment is overly permissive | MEDIUM |

## GCP checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| BUCKET_PUBLIC_ACCESS | GCS bucket allows public access | HIGH |
| FIREWALL_OPEN | GCP firewall rule allows 0.0.0.0/0 on management ports | HIGH |
| IAM_PRIMITIVE_ROLE | IAM primitive role (owner/editor/viewer) assigned | MEDIUM |

## Kubernetes checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| POD_ROOT_USER | Container runs as root | HIGH |
| PRIVILEGE_ESCALATION | Privilege escalation allowed | HIGH |
| HOST_NETWORK | Pod uses host network namespace | MEDIUM |

## Docker checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| ROOT_USER | Container runs as root | HIGH |
| SENSITIVE_ENV | Environment variable exposes sensitive data | MEDIUM |
| NO_HEALTHCHECK | Container missing health check | LOW |

## Configuration

Cloud provider credentials are read from:

- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AZURE_CLIENT_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.
- **Default credential chains**: Each SDK's standard credential resolution (instance profiles, `~/.aws/credentials`, etc.)
- **Credential store**: `siyarix creds set <provider> <key>`

## Output

Results include: check ID, title, severity, description, and remediation guidance.

```bash
siyarix scan --cloud aws --format json
```
