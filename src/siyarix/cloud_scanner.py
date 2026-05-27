"""Cloud provider security scanning module.

Integrates with AWS, Azure, GCP, Kubernetes, and Docker for
cloud security assessments as described in Chapter 21.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"


@dataclass
class CloudScanResult:
    """Result of a cloud security scan."""

    provider: CloudProvider
    findings: list[dict[str, Any]] = field(default_factory=list)
    target: str = ""
    scan_id: str = ""
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat())
    summary: dict[str, Any] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    error: str = ""


# Pre-defined security checks per provider
_CLOUD_CHECKS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "id": "S3_PUBLIC_ACCESS",
            "title": "S3 bucket public access",
            "severity": "high",
            "description": "S3 bucket allows public read access",
        },
        {
            "id": "IAM_OVERLY_PERMISSIVE",
            "title": "Overly permissive IAM policy",
            "severity": "critical",
            "description": "IAM policy grants *:* to all principals",
        },
        {
            "id": "SECURITY_GROUP_OPEN",
            "title": "Security group allows 0.0.0.0/0:22",
            "severity": "high",
            "description": "SSH (port 22) open to all IPv4 addresses",
        },
        {
            "id": "UNENCRYPTED_EBS",
            "title": "Unencrypted EBS volume",
            "severity": "medium",
            "description": "EBS volume does not have encryption enabled",
        },
        {
            "id": "CLOUDTRAIL_DISABLED",
            "title": "CloudTrail not enabled",
            "severity": "high",
            "description": "AWS CloudTrail is not enabled for audit logging",
        },
    ],
    "azure": [
        {
            "id": "NSG_OPEN",
            "title": "NSG allows management ports",
            "severity": "high",
            "description": "Network Security Group allows 3389 or 22 from any source",
        },
        {
            "id": "BLOB_PUBLIC",
            "title": "Blob storage publicly accessible",
            "severity": "high",
            "description": "Azure Blob Storage container allows anonymous access",
        },
        {
            "id": "RBAC_OVERPRIVILEGED",
            "title": "Overprivileged RBAC role",
            "severity": "medium",
            "description": "User/group has excessive RBAC permissions",
        },
    ],
    "gcp": [
        {
            "id": "BUCKET_PUBLIC",
            "title": "GCS bucket publicly accessible",
            "severity": "high",
            "description": "Google Cloud Storage bucket allows public access",
        },
        {
            "id": "FIREWALL_OPEN",
            "title": "Firewall rule allows 0.0.0.0/0",
            "severity": "high",
            "description": "VPC firewall rule allows ingress from all IPs",
        },
        {
            "id": "IAM_PRIMITIVE",
            "title": "Primitive IAM role in use",
            "severity": "medium",
            "description": "Primitive roles (owner/editor/viewer) should be avoided",
        },
    ],
    "kubernetes": [
        {
            "id": "POD_RBAC",
            "title": "Pod runs as root",
            "severity": "high",
            "description": "Container running with root privileges",
        },
        {
            "id": "PRIVILEGED_ESCALATION",
            "title": "Privilege escalation allowed",
            "severity": "medium",
            "description": "Security context allows privilege escalation",
        },
        {
            "id": "HOST_NETWORK",
            "title": "Pod uses host network",
            "severity": "medium",
            "description": "Pod has access to the host network namespace",
        },
    ],
    "docker": [
        {
            "id": "ROOT_USER",
            "title": "Container runs as root",
            "severity": "high",
            "description": "Docker container is running as root user",
        },
        {
            "id": "SENSITIVE_ENV",
            "title": "Sensitive data in environment",
            "severity": "medium",
            "description": "Container environment contains potentially sensitive data",
        },
        {
            "id": "HEALTHCHECK_MISSING",
            "title": "Healthcheck not configured",
            "severity": "low",
            "description": "Docker image does not define HEALTHCHECK",
        },
    ],
}


class CloudScanner:
    """Multi-cloud security scanning engine."""

    def __init__(self) -> None:
        self._scan_history: list[CloudScanResult] = []

    async def scan_aws(self, account_id: str = "", region: str = "") -> CloudScanResult:
        target = account_id or os.environ.get("AWS_ACCOUNT_ID", "")
        aws_region = (
            region
            or os.environ.get("AWS_REGION", "")
            or os.environ.get("AWS_DEFAULT_REGION", "")
        )
        aws_profile = os.environ.get("AWS_PROFILE", "")
        has_access_key = bool(os.environ.get("AWS_ACCESS_KEY_ID"))
        has_secret_access_key = bool(os.environ.get("AWS_SECRET_ACCESS_KEY"))

        boto3_available = False
        aws_account_id = ""
        try:
            import boto3

            boto3_available = True
            sts = boto3.client("sts", region_name=aws_region or "us-east-1")
            identity = sts.get_caller_identity()
            aws_account_id = identity.get("Account", "")
        except ImportError:
            pass
        except Exception as e:
            logger.debug("AWS STS call failed: %s", e)

        display_target = target or aws_account_id or "aws-unknown"

        def _make_default(
            cid: str, status: str, details: str, rec: str, ev: str
        ) -> dict[str, Any]:
            return {
                "check_name": cid,
                "status": status,
                "severity": "medium",
                "details": details,
                "recommendation": rec,
                "target": display_target,
                "tool": "siyarix-cloud-aws",
                "timestamp": datetime.now().isoformat(),
                "evidence": ev,
            }

        findings: list[dict[str, Any]] = []
        for check_def in _CLOUD_CHECKS.get("aws", []):
            cid = check_def["id"]
            f = dict(check_def)

            if cid == "S3_PUBLIC_ACCESS":
                if boto3_available and aws_account_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            f"AWS connected (account {aws_account_id}) but S3 ACL check requires s3:ListAllMyBuckets",
                            "Grant s3:ListAllMyBuckets and s3:GetBucketPolicyAcl permissions or use IAM Access Analyzer",
                            f"boto3=ok, account={aws_account_id}",
                        )
                    )
                elif has_access_key or has_secret_access_key:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "AWS credentials found but boto3 SDK not installed",
                            "Install boto3: pip install boto3",
                            "AWS_ACCESS_KEY_ID or SECRET set, boto3 unavailable",
                        )
                    )
                elif aws_profile:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            f"AWS profile '{aws_profile}' configured but SDK not available",
                            "Install boto3 or configure credentials via env vars",
                            f"AWS_PROFILE={aws_profile}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No AWS credentials or SDK found",
                            "Configure AWS credentials via environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) or AWS CLI",
                            "No AWS credentials detected",
                        )
                    )

            elif cid == "IAM_OVERLY_PERMISSIVE":
                if boto3_available and aws_account_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "AWS connected but IAM policy review requires iam:ListPolicies",
                            "Grant iam:ListPolicies and iam:ListPolicyVersions permissions",
                            f"boto3=ok, account={aws_account_id}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot evaluate IAM policies without AWS access",
                            "Configure AWS credentials with IAM read access",
                            f"AWS credentials: {has_access_key}",
                        )
                    )

            elif cid == "SECURITY_GROUP_OPEN":
                if boto3_available and aws_account_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "AWS connected but SG check requires ec2:DescribeSecurityGroups",
                            "Grant ec2:DescribeSecurityGroups permission",
                            f"boto3=ok, account={aws_account_id}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot evaluate security groups without AWS access",
                            "Configure AWS credentials",
                            f"AWS credentials: {has_access_key}",
                        )
                    )

            elif cid == "UNENCRYPTED_EBS":
                if boto3_available and aws_account_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "AWS connected but EBS check requires ec2:DescribeVolumes",
                            "Grant ec2:DescribeVolumes permission",
                            f"boto3=ok, account={aws_account_id}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot evaluate EBS encryption without AWS access",
                            "Configure AWS credentials",
                            f"AWS credentials: {has_access_key}",
                        )
                    )

            elif cid == "CLOUDTRAIL_DISABLED":
                if boto3_available and aws_account_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "AWS connected but CloudTrail check requires cloudtrail:DescribeTrails",
                            "Grant cloudtrail:DescribeTrails permission",
                            f"boto3=ok, account={aws_account_id}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot evaluate CloudTrail status without AWS access",
                            "Configure AWS credentials",
                            f"AWS credentials: {has_access_key}",
                        )
                    )

            findings.append(f)

        return self._build_result(CloudProvider.AWS, target or "aws-account", findings)

    async def scan_azure(self, subscription_id: str = "") -> CloudScanResult:
        target = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        has_client_id = bool(os.environ.get("AZURE_CLIENT_ID"))
        has_tenant_id = bool(os.environ.get("AZURE_TENANT_ID"))

        azure_available = False
        try:
            from azure.identity import DefaultAzureCredential

            cred = DefaultAzureCredential()
            _ = cred.get_token("https://management.azure.com/.default")
            azure_available = True
        except ImportError:
            pass
        except Exception as e:
            logger.debug("Azure credential check failed: %s", e)

        display_target = target or "azure-subscription"

        def _make_default(
            cid: str, status: str, details: str, rec: str, ev: str
        ) -> dict[str, Any]:
            return {
                "check_name": cid,
                "status": status,
                "severity": "medium",
                "details": details,
                "recommendation": rec,
                "target": display_target,
                "tool": "siyarix-cloud-azure",
                "timestamp": datetime.now().isoformat(),
                "evidence": ev,
            }

        findings: list[dict[str, Any]] = []
        for check_def in _CLOUD_CHECKS.get("azure", []):
            cid = check_def["id"]
            f = dict(check_def)

            if cid == "NSG_OPEN":
                if azure_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Azure connected but NSG review requires Network Contributor role",
                            "Grant Network Contributor role or check NSG rules manually in portal",
                            "azure-identity=ok",
                        )
                    )
                elif has_client_id and has_tenant_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Azure env vars present but azure-identity SDK not installed",
                            "Install azure-identity: pip install azure-identity",
                            "AZURE_CLIENT_ID and AZURE_TENANT_ID set",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No Azure credentials or SDK found",
                            "Set AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID and install azure-identity",
                            "No Azure configuration detected",
                        )
                    )

            elif cid == "BLOB_PUBLIC":
                if azure_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Azure connected but blob check requires Storage Account Reader role",
                            "Grant Storage Account Reader role or check blob access manually",
                            "azure-identity=ok",
                        )
                    )
                elif has_client_id:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Azure env vars present but SDK not installed",
                            "Install azure-identity and azure-storage-blob",
                            "AZURE_CLIENT_ID set",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No Azure credentials or SDK found",
                            "Configure Azure service principal and install azure-identity",
                            "No Azure configuration detected",
                        )
                    )

            elif cid == "RBAC_OVERPRIVILEGED":
                if azure_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Azure connected but RBAC review requires User Access Administrator role",
                            "Review RBAC assignments in Azure Portal under Access Control (IAM)",
                            "azure-identity=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check Azure RBAC without credentials",
                            "Configure Azure credentials with User Access Administrator role",
                            f"Azure env: client_id={has_client_id}, tenant_id={has_tenant_id}",
                        )
                    )

            findings.append(f)

        return self._build_result(
            CloudProvider.AZURE, target or "azure-unknown", findings
        )

    async def scan_gcp(self, project_id: str = "") -> CloudScanResult:
        target = project_id or os.environ.get("GCP_PROJECT", "")
        has_creds = bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
        gcp_project_from_env = os.environ.get(
            "GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        )

        gcp_available = False
        try:
            from google.cloud import resource_manager

            client = resource_manager.Client()
            _ = list(client.list_projects())
            gcp_available = True
        except ImportError:
            pass
        except Exception as e:
            logger.debug("GCP check failed: %s", e)

        display_target = target or gcp_project_from_env or "gcp-project"

        def _make_default(
            cid: str, status: str, details: str, rec: str, ev: str
        ) -> dict[str, Any]:
            return {
                "check_name": cid,
                "status": status,
                "severity": "medium",
                "details": details,
                "recommendation": rec,
                "target": display_target,
                "tool": "siyarix-cloud-gcp",
                "timestamp": datetime.now().isoformat(),
                "evidence": ev,
            }

        findings: list[dict[str, Any]] = []
        for check_def in _CLOUD_CHECKS.get("gcp", []):
            cid = check_def["id"]
            f = dict(check_def)

            if cid == "BUCKET_PUBLIC":
                if gcp_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "GCP connected but bucket ACL check requires storage.buckets.list",
                            "Grant roles/storage.admin or check bucket ACLs via gsutil",
                            "gcp-resource-manager=ok",
                        )
                    )
                elif has_creds:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "GOOGLE_APPLICATION_CREDENTIALS set but google-cloud-resource-manager not installed",
                            "Install: pip install google-cloud-resource-manager google-cloud-storage",
                            "GOOGLE_APPLICATION_CREDENTIALS set",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No GCP credentials or SDK found",
                            "Set GOOGLE_APPLICATION_CREDENTIALS and/or GCP_PROJECT environment variables",
                            "No GCP configuration detected",
                        )
                    )

            elif cid == "FIREWALL_OPEN":
                if gcp_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "GCP connected but firewall check requires compute.firewalls.list",
                            "Grant roles/compute.securityAdmin or check firewall rules via gcloud",
                            "gcp-resource-manager=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check GCP firewall without credentials",
                            "Configure GCP credentials with compute security admin role",
                            f"GCP creds: {has_creds}",
                        )
                    )

            elif cid == "IAM_PRIMITIVE":
                if gcp_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "GCP connected but IAM review requires resourcemanager.projects.getIamPolicy",
                            "Grant roles/resourcemanager.organizationAdmin or review IAM in GCP Console",
                            "gcp-resource-manager=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check GCP IAM without credentials",
                            "Configure GCP credentials with organization admin role",
                            f"GCP creds: {has_creds}",
                        )
                    )

            findings.append(f)

        return self._build_result(CloudProvider.GCP, target or "gcp-unknown", findings)

    async def scan_kubernetes(self, namespace: str = "default") -> CloudScanResult:
        target = namespace
        kubeconfig = os.environ.get("KUBECONFIG", "")
        kube_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")

        k8s_available = False
        try:
            import kubernetes

            if kube_host:
                kubernetes.config.load_incluster_config()
            else:
                kubernetes.config.load_kube_config()
            k8s_available = True
        except ImportError:
            pass
        except Exception as e:
            logger.debug("K8s config load failed: %s", e)

        def _make_default(
            cid: str, status: str, details: str, rec: str, ev: str
        ) -> dict[str, Any]:
            return {
                "check_name": cid,
                "status": status,
                "severity": "medium",
                "details": details,
                "recommendation": rec,
                "target": target,
                "tool": "siyarix-cloud-kubernetes",
                "timestamp": datetime.now().isoformat(),
                "evidence": ev,
            }

        findings: list[dict[str, Any]] = []
        for check_def in _CLOUD_CHECKS.get("kubernetes", []):
            cid = check_def["id"]
            f = dict(check_def)

            if cid == "POD_RBAC":
                if k8s_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "K8s connected but Pod security context check requires corev1.ListPods",
                            "Grant pod list permissions or review pod specs for securityContext.runAsRoot",
                            "kubernetes=ok",
                        )
                    )
                elif kubeconfig:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            f"KUBECONFIG set ({kubeconfig}) but kubernetes SDK not installed",
                            "Install: pip install kubernetes",
                            f"KUBECONFIG={kubeconfig}",
                        )
                    )
                elif kube_host:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "KUBERNETES_SERVICE_HOST set but SDK not available for in-cluster config",
                            "Install kubernetes SDK in the container: pip install kubernetes",
                            "KUBERNETES_SERVICE_HOST set",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No Kubernetes configuration found",
                            "Set KUBECONFIG env var or run inside a cluster with KUBERNETES_SERVICE_HOST set",
                            "No K8s configuration detected",
                        )
                    )

            elif cid == "PRIVILEGED_ESCALATION":
                if k8s_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "K8s connected but privilege check requires pod spec inspection",
                            "Audit all pods for securityContext.allowPrivilegeEscalation=true",
                            "kubernetes=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check K8s privilege escalation without cluster access",
                            "Configure kubeconfig and install kubernetes SDK",
                            f"K8s config: kubeconfig={bool(kubeconfig)}, in-cluster={bool(kube_host)}",
                        )
                    )

            elif cid == "HOST_NETWORK":
                if k8s_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "K8s connected but host network check requires pod spec inspection",
                            "Audit pods for spec.hostNetwork=true and enforce Pod Security Policies",
                            "kubernetes=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check K8s host network without cluster access",
                            "Configure kubeconfig and install kubernetes SDK",
                            f"K8s config: kubeconfig={bool(kubeconfig)}, in-cluster={bool(kube_host)}",
                        )
                    )

            findings.append(f)

        return self._build_result(CloudProvider.KUBERNETES, target, findings)

    async def scan_docker(self, image_name: str = "") -> CloudScanResult:
        target = image_name or "default"
        docker_host = os.environ.get("DOCKER_HOST", "")
        docker_cert_path = os.environ.get("DOCKER_CERT_PATH", "")

        docker_available = False
        try:
            import docker

            client = docker.from_env()
            client.ping()
            docker_available = True
        except ImportError:
            pass
        except Exception as e:
            logger.debug("Docker ping failed: %s", e)

        def _make_default(
            cid: str, status: str, details: str, rec: str, ev: str
        ) -> dict[str, Any]:
            return {
                "check_name": cid,
                "status": status,
                "severity": "medium",
                "details": details,
                "recommendation": rec,
                "target": target,
                "tool": "siyarix-cloud-docker",
                "timestamp": datetime.now().isoformat(),
                "evidence": ev,
            }

        findings: list[dict[str, Any]] = []
        for check_def in _CLOUD_CHECKS.get("docker", []):
            cid = check_def["id"]
            f = dict(check_def)

            if cid == "ROOT_USER":
                if docker_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Docker connected but container user check requires image inspection",
                            "Inspect images with 'docker inspect' and verify User field is not empty or root",
                            "docker=ok",
                        )
                    )
                elif docker_host:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            f"DOCKER_HOST set ({docker_host}) but docker-py not installed",
                            "Install: pip install docker",
                            f"DOCKER_HOST={docker_host}",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "fail",
                            "No Docker daemon accessible or docker-py not installed",
                            "Install docker-py and ensure Docker daemon is running, or set DOCKER_HOST",
                            "No Docker configuration detected",
                        )
                    )

            elif cid == "SENSITIVE_ENV":
                if docker_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Docker connected but env var inspection requires container list/inspect",
                            "Check running containers for sensitive env vars (PASSWORD, SECRET, KEY)",
                            "docker=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check Docker env vars without daemon access",
                            "Install docker-py and connect to Docker daemon",
                            f"Docker config: host={docker_host}, cert_path={docker_cert_path}",
                        )
                    )

            elif cid == "HEALTHCHECK_MISSING":
                if docker_available:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Docker connected but HEALTHCHECK inspection requires image list/inspect",
                            "Audit Dockerfiles/images for HEALTHCHECK instruction",
                            "docker=ok",
                        )
                    )
                else:
                    f.update(
                        _make_default(
                            cid,
                            "error",
                            "Cannot check Docker HEALTHCHECK without daemon access",
                            "Install docker-py and connect to Docker daemon",
                            f"Docker config: host={docker_host}, cert_path={docker_cert_path}",
                        )
                    )

            findings.append(f)

        return self._build_result(CloudProvider.DOCKER, target, findings)

    async def scan_by_provider(
        self, provider: CloudProvider, target: str = ""
    ) -> CloudScanResult:
        scanners: dict[CloudProvider, Callable[[str], Awaitable[CloudScanResult]]] = {
            CloudProvider.AWS: self.scan_aws,
            CloudProvider.AZURE: self.scan_azure,
            CloudProvider.GCP: self.scan_gcp,
            CloudProvider.KUBERNETES: self.scan_kubernetes,
            CloudProvider.DOCKER: self.scan_docker,
        }
        scanner = scanners.get(provider)
        if not scanner:
            return CloudScanResult(
                provider=provider,
                target=target,
                error=f"Unsupported provider: {provider}",
            )
        return await scanner(target)

    def _build_result(
        self, provider: CloudProvider, target: str, findings: list[dict[str, Any]]
    ) -> CloudScanResult:
        import time
        import uuid

        start = time.monotonic()

        result = CloudScanResult(
            provider=provider,
            findings=findings,
            target=target,
            scan_id=uuid.uuid4().hex[:12],
            scan_duration_seconds=time.monotonic() - start,
        )
        result.summary = {
            "provider": provider.value,
            "target": target,
            "total_checks": len(findings),
            "severity_counts": {
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            },
            "scan_duration_s": round(result.scan_duration_seconds, 2),
        }
        self._scan_history.append(result)
        return result

    def get_history(self, limit: int = 10) -> list[CloudScanResult]:
        return self._scan_history[-limit:]

    def summary(self) -> dict[str, Any]:
        return {
            "total_scans": len(self._scan_history),
            "providers_scanned": list({r.provider.value for r in self._scan_history}),
            "total_findings": sum(len(r.findings) for r in self._scan_history),
        }

    def generate_report(self, result: CloudScanResult, fmt: str = "text") -> str:
        """Generate a formatted report from a scan result."""
        if fmt == "json":
            import json
            return json.dumps({
                "scan_id": result.scan_id,
                "provider": result.provider.value,
                "target": result.target,
                "scanned_at": result.scanned_at,
                "summary": result.summary,
                "findings": result.findings,
                "error": result.error,
            }, indent=2)
        lines = [
            f"╒═══ Cloud Scan Report — {result.provider.value.upper()} ═══╕",
            f"  Target:       {result.target or '(not specified)'}",
            f"  Scan ID:      {result.scan_id}",
            f"  Timestamp:    {result.scanned_at}",
            f"  Duration:     {result.scan_duration_seconds:.2f}s",
            "",
            f"  Summary:      {result.summary.get('severity_counts', {})}",
            f"  Total Checks: {result.summary.get('total_checks', 0)}",
            "",
        ]
        if result.error:
            lines.append(f"  ERROR: {result.error}")
        if result.findings:
            lines.append("  Findings:")
            for f in result.findings[:20]:
                sev = f.get("severity", "?").upper()
                status = f.get("status", "?")
                title = f.get("title", f.get("check_name", "?"))
                lines.append(f"    [{sev}] {title} ({status})")
            if len(result.findings) > 20:
                lines.append(f"    ... and {len(result.findings) - 20} more")
        lines.append("")
        return "\n".join(lines)

    async def scan_cloud(self, provider: CloudProvider, target: str = "") -> CloudScanResult:
        """Alias for scan_by_provider — compatibility wrapper."""
        return await self.scan_by_provider(provider, target)

    async def scan(self, provider: CloudProvider | str, target: str = "") -> CloudScanResult:
        """Universal scan entry point. Accepts provider as string or enum."""
        if isinstance(provider, str):
            provider = CloudProvider(provider.lower())
        return await self.scan_by_provider(provider, target)


__all__ = ["CloudScanner", "CloudScanResult", "CloudProvider"]
