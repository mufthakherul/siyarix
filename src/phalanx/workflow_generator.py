"""Phalanx AI Workflow Generator — Generate YAML workflow definitions from natural language.

Provides:
  • **WorkflowGenerator** — Converts NL goals into structured YAML workflows
  • **WorkflowTemplate** — Predefined workflow templates for common operations
  • **WorkflowValidator** — Validates generated workflows before execution

The generator uses the planner's AI models to decompose high-level goals
into step-by-step workflows that can be saved, shared, and re-executed.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

__all__ = [
    "WorkflowGenerator",
    "WorkflowTemplate",
    "WorkflowValidator",
    "GeneratedWorkflow",
]

logger = logging.getLogger(__name__)


# ── Predefined templates ────────────────────────────────────────────────


class TemplateCategory(StrEnum):
    RECON = "recon"
    SCAN = "scan"
    WEBAPP = "webapp"
    NETWORK = "network"
    PENTEST = "pentest"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


@dataclass
class WorkflowTemplate:
    """A predefined workflow template."""

    name: str
    category: TemplateCategory
    description: str
    steps: list[dict[str, Any]]
    variables: list[str] = field(default_factory=list)
    estimated_duration: str = ""
    risk_level: str = "low"

    def render(self, **variables: str) -> dict[str, Any]:
        """Render the template with variable substitution."""
        import json

        rendered = json.dumps(self.steps)
        for key, value in variables.items():
            rendered = rendered.replace(f"${{{key}}}", value)
            rendered = rendered.replace(f"$({key})", value)
        return {
            "name": self.name,
            "category": self.category.value,
            "steps": json.loads(rendered),
            "variables": variables,
        }


# Built-in templates
BUILTIN_TEMPLATES: dict[str, WorkflowTemplate] = {
    "full-recon": WorkflowTemplate(
        name="Full Reconnaissance",
        category=TemplateCategory.RECON,
        description="Complete target reconnaissance: DNS, subdomains, ports, services",
        variables=["target"],
        estimated_duration="15-30 min",
        risk_level="low",
        steps=[
            {
                "id": "dns",
                "tool": "dig",
                "args": ["${target}", "ANY"],
                "description": "DNS enumeration",
            },
            {
                "id": "whois",
                "tool": "whois",
                "args": ["${target}"],
                "description": "WHOIS lookup",
            },
            {
                "id": "subfinder",
                "tool": "subfinder",
                "args": ["-d", "${target}"],
                "description": "Subdomain enumeration",
            },
            {
                "id": "nmap-quick",
                "tool": "nmap",
                "args": ["-sV", "-T4", "--top-ports", "1000", "${target}"],
                "depends_on": ["dns"],
                "description": "Quick port scan",
            },
            {
                "id": "report",
                "step_type": "report",
                "depends_on": ["nmap-quick", "subfinder", "whois"],
                "description": "Generate recon report",
            },
        ],
    ),
    "webapp-scan": WorkflowTemplate(
        name="Web Application Scan",
        category=TemplateCategory.WEBAPP,
        description="Full web application vulnerability assessment",
        variables=["target_url"],
        estimated_duration="30-60 min",
        risk_level="medium",
        steps=[
            {
                "id": "httpx",
                "tool": "httpx",
                "args": ["-u", "${target_url}", "-tech-detect"],
                "description": "HTTP probe and tech detection",
            },
            {
                "id": "nuclei",
                "tool": "nuclei",
                "args": ["-u", "${target_url}", "-severity", "critical,high,medium"],
                "depends_on": ["httpx"],
                "description": "Vulnerability scan with Nuclei",
            },
            {
                "id": "nikto",
                "tool": "nikto",
                "args": ["-h", "${target_url}"],
                "depends_on": ["httpx"],
                "description": "Web server misconfiguration scan",
            },
            {
                "id": "gobuster",
                "tool": "gobuster",
                "args": [
                    "dir",
                    "-u",
                    "${target_url}",
                    "-w",
                    "/usr/share/wordlists/dirb/common.txt",
                ],
                "depends_on": ["httpx"],
                "description": "Directory enumeration",
            },
            {
                "id": "report",
                "step_type": "report",
                "depends_on": ["nuclei", "nikto", "gobuster"],
                "description": "Generate webapp assessment report",
            },
        ],
    ),
    "network-sweep": WorkflowTemplate(
        name="Network Sweep",
        category=TemplateCategory.NETWORK,
        description="Discover and enumerate hosts on a network range",
        variables=["network_range"],
        estimated_duration="10-20 min",
        risk_level="low",
        steps=[
            {
                "id": "ping-sweep",
                "tool": "nmap",
                "args": ["-sn", "${network_range}"],
                "description": "Host discovery ping sweep",
            },
            {
                "id": "port-scan",
                "tool": "nmap",
                "args": ["-sV", "-T4", "-iL", "live_hosts.txt"],
                "depends_on": ["ping-sweep"],
                "description": "Service version scan of live hosts",
            },
            {
                "id": "vuln-scan",
                "tool": "nmap",
                "args": ["--script", "vuln", "-iL", "live_hosts.txt"],
                "depends_on": ["port-scan"],
                "description": "Vulnerability script scan",
            },
            {
                "id": "report",
                "step_type": "report",
                "depends_on": ["vuln-scan"],
                "description": "Generate network assessment report",
            },
        ],
    ),
    "quick-check": WorkflowTemplate(
        name="Quick Security Check",
        category=TemplateCategory.SCAN,
        description="Fast security check — ports + critical vulns only",
        variables=["target"],
        estimated_duration="5-10 min",
        risk_level="low",
        steps=[
            {
                "id": "ports",
                "tool": "nmap",
                "args": ["-sV", "--top-ports", "100", "${target}"],
                "description": "Top 100 ports scan",
            },
            {
                "id": "vulns",
                "tool": "nuclei",
                "args": ["-u", "${target}", "-severity", "critical,high"],
                "depends_on": ["ports"],
                "description": "Critical vulnerability check",
            },
            {
                "id": "report",
                "step_type": "report",
                "depends_on": ["vulns"],
                "description": "Quick security report",
            },
        ],
    ),
}


@dataclass
class GeneratedWorkflow:
    """A workflow generated by the AI or from a template."""

    workflow_id: str
    name: str
    description: str
    steps: list[dict[str, Any]]
    source: str  # "ai" | "template" | "custom"
    template_name: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    variables: dict[str, str] = field(default_factory=dict)
    estimated_duration: str = ""
    risk_level: str = "low"

    def to_yaml_dict(self) -> dict[str, Any]:
        """Convert to a dict suitable for YAML serialization."""
        return {
            "workflow": {
                "id": self.workflow_id,
                "name": self.name,
                "description": self.description,
                "source": self.source,
                "created_at": self.created_at,
                "risk_level": self.risk_level,
                "estimated_duration": self.estimated_duration,
                "variables": self.variables,
                "steps": self.steps,
            }
        }

    def save_yaml(self, path: Path) -> None:
        """Save workflow to a YAML file."""
        try:
            import yaml

            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                yaml.dump(
                    self.to_yaml_dict(), fh, default_flow_style=False, sort_keys=False
                )
            logger.info("Workflow saved to %s", path)
        except ImportError:
            # Fallback: save as JSON
            import json

            json_path = path.with_suffix(".json")
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(self.to_yaml_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            logger.info(
                "Workflow saved as JSON to %s (pyyaml not installed)", json_path
            )


class WorkflowValidator:
    """Validate a generated workflow before execution."""

    def validate(self, workflow: GeneratedWorkflow) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []

        if not workflow.steps:
            errors.append("Workflow has no steps")

        step_ids = set()
        for i, step in enumerate(workflow.steps):
            step_id = step.get("id", "")
            if not step_id:
                errors.append(f"Step {i} has no 'id' field")
            elif step_id in step_ids:
                errors.append(f"Duplicate step id: {step_id}")
            step_ids.add(step_id)

            # Check dependencies reference valid step IDs
            deps = step.get("depends_on", [])
            for dep in deps:
                if dep not in step_ids:
                    errors.append(f"Step '{step_id}' depends on unknown step '{dep}'")

            # Check for required fields
            if not step.get("tool") and step.get("step_type") != "report":
                if not step.get("command"):
                    errors.append(f"Step '{step_id}' has no 'tool' or 'command'")

        return errors


class WorkflowGenerator:
    """Generate workflows from natural language or templates.

    Usage::

        gen = WorkflowGenerator()

        # From template
        wf = gen.from_template("full-recon", target="example.com")

        # From natural language (uses AI planner)
        wf = await gen.from_natural_language("Full pentest of target.com")

        # List available templates
        templates = gen.list_templates()
    """

    def __init__(self) -> None:
        self._validator = WorkflowValidator()

    def list_templates(self) -> list[dict[str, Any]]:
        """List all available workflow templates."""
        return [
            {
                "name": t.name,
                "key": key,
                "category": t.category.value,
                "description": t.description,
                "variables": t.variables,
                "estimated_duration": t.estimated_duration,
                "risk_level": t.risk_level,
                "step_count": len(t.steps),
            }
            for key, t in BUILTIN_TEMPLATES.items()
        ]

    def from_template(self, template_key: str, **variables: str) -> GeneratedWorkflow:
        """Generate a workflow from a predefined template."""
        template = BUILTIN_TEMPLATES.get(template_key)
        if not template:
            available = ", ".join(BUILTIN_TEMPLATES.keys())
            raise ValueError(
                f"Unknown template: {template_key}. Available: {available}"
            )

        rendered = template.render(**variables)
        wf = GeneratedWorkflow(
            workflow_id=f"wf_{str(uuid.uuid4())[:8]}",
            name=template.name,
            description=template.description,
            steps=rendered["steps"],
            source="template",
            template_name=template_key,
            variables=variables,
            estimated_duration=template.estimated_duration,
            risk_level=template.risk_level,
        )

        errors = self._validator.validate(wf)
        if errors:
            logger.warning("Template workflow has validation issues: %s", errors)

        return wf

    async def from_natural_language(
        self,
        goal: str,
        target: str = "",
        context: dict[str, Any] | None = None,
    ) -> GeneratedWorkflow:
        """Generate a workflow from a natural language goal description.

        This method constructs a prompt for the AI planner and parses the
        response into a structured workflow.
        """
        # Build a synthetic workflow from the goal
        # In a full implementation, this would call the planner's AI models
        steps = self._decompose_goal(goal, target)

        wf = GeneratedWorkflow(
            workflow_id=f"wf_{str(uuid.uuid4())[:8]}",
            name=f"AI Generated: {goal[:60]}",
            description=goal,
            steps=steps,
            source="ai",
            variables={"target": target} if target else {},
            risk_level=self._estimate_risk(goal),
        )

        errors = self._validator.validate(wf)
        if errors:
            logger.warning("AI workflow has validation issues: %s", errors)

        return wf

    def _decompose_goal(self, goal: str, target: str) -> list[dict[str, Any]]:
        """Heuristic goal decomposition into workflow steps.

        This provides a baseline decomposition. The full AI-powered version
        will be implemented when integrated with the planner.
        """
        goal_lower = goal.lower()
        steps: list[dict[str, Any]] = []
        step_num = 0

        # Recon keywords
        if any(
            kw in goal_lower
            for kw in ["recon", "reconnaissance", "discover", "enumerate"]
        ):
            step_num += 1
            steps.append(
                {
                    "id": f"step_{step_num}",
                    "tool": "nmap",
                    "args": ["-sV", "-T4", target or "${target}"],
                    "description": "Service enumeration",
                }
            )

        # Scan keywords
        if any(kw in goal_lower for kw in ["scan", "vulnerability", "vuln", "assess"]):
            step_num += 1
            depends = [f"step_{step_num - 1}"] if steps else []
            steps.append(
                {
                    "id": f"step_{step_num}",
                    "tool": "nuclei",
                    "args": ["-u", target or "${target}"],
                    "depends_on": depends,
                    "description": "Vulnerability scanning",
                }
            )

        # Web keywords
        if any(
            kw in goal_lower
            for kw in ["web", "http", "webapp", "application", "sql", "xss"]
        ):
            step_num += 1
            depends = [f"step_{step_num - 1}"] if steps else []
            steps.append(
                {
                    "id": f"step_{step_num}",
                    "tool": "nikto",
                    "args": ["-h", target or "${target}"],
                    "depends_on": depends,
                    "description": "Web application scanning",
                }
            )

        # Subdomain keywords
        if any(kw in goal_lower for kw in ["subdomain", "dns", "domain"]):
            step_num += 1
            steps.append(
                {
                    "id": f"step_{step_num}",
                    "tool": "subfinder",
                    "args": ["-d", target or "${target}"],
                    "description": "Subdomain enumeration",
                }
            )

        # Directory keywords
        if any(kw in goal_lower for kw in ["directory", "dir", "brute", "fuzz"]):
            step_num += 1
            depends = [f"step_{step_num - 1}"] if steps else []
            steps.append(
                {
                    "id": f"step_{step_num}",
                    "tool": "gobuster",
                    "args": [
                        "dir",
                        "-u",
                        target or "${target}",
                        "-w",
                        "/usr/share/wordlists/dirb/common.txt",
                    ],
                    "depends_on": depends,
                    "description": "Directory brute-forcing",
                }
            )

        # Fallback — generic scan
        if not steps:
            steps.append(
                {
                    "id": "step_1",
                    "tool": "nmap",
                    "args": ["-sV", "-T4", target or "${target}"],
                    "description": f"Automated scan for: {goal[:80]}",
                }
            )

        # Always add report step
        step_num += 1
        steps.append(
            {
                "id": f"step_{step_num}",
                "step_type": "report",
                "depends_on": [s["id"] for s in steps],
                "description": "Generate findings report",
            }
        )

        return steps

    def _estimate_risk(self, goal: str) -> str:
        """Estimate risk level from goal keywords."""
        goal_lower = goal.lower()
        if any(
            kw in goal_lower
            for kw in ["exploit", "attack", "payload", "reverse shell", "brute force"]
        ):
            return "high"
        if any(
            kw in goal_lower for kw in ["scan", "vulnerability", "pentest", "inject"]
        ):
            return "medium"
        return "low"
