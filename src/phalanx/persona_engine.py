"""Persona Engine — behavioral profiles for Phalanx operations.

As described in Chapter 4 of the architecture:
- Built-in personas with system prompts, tool ACLs, workflow templates, learning bias
- Custom persona creation, storage, and sharing
- Auto persona detection via intent classification
- Hot-swapping with ~200ms context switch latency
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_PERSONAS_DIR = _PHALANX_HOME / "personas"
_CUSTOM_DIR = _PERSONAS_DIR / "custom"


class PersonaName(StrEnum):
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    BUG_HUNTER = "bug_hunter"
    PENTESTER = "pentester"
    SOC_ANALYST = "soc_analyst"
    NONE = "none"
    AUTO = "auto"


class LearningBias(StrEnum):
    AGGRESSIVE = "aggressive"
    CAUTIOUS = "cautious"
    METHODICAL = "methodical"
    TIME_SENSITIVE = "time_sensitive"
    ADAPTIVE = "adaptive"
    BALANCED = "balanced"


@dataclass
class ToolACL:
    allowed: list[str] = field(default_factory=lambda: ["*"])
    forbidden: list[str] = field(default_factory=list)
    permission_required: list[str] = field(default_factory=list)
    auto_approve_seconds: int = 10

    def is_allowed(self, tool: str) -> bool:
        if tool in self.forbidden:
            return False
        if "*" in self.allowed:
            return True
        return tool in self.allowed

    def requires_permission(self, tool: str) -> bool:
        return tool in self.permission_required


@dataclass
class WorkflowTemplate:
    steps: list[str] = field(default_factory=list)

    def to_list(self) -> list[str]:
        return list(self.steps)


@dataclass
class Persona:
    name: str
    system_prompt: str
    description: str = ""
    tool_acl: ToolACL = field(default_factory=ToolACL)
    workflow_template: WorkflowTemplate = field(default_factory=WorkflowTemplate)
    learning_bias: LearningBias = LearningBias.BALANCED
    tool_filter_category: list[str] = field(default_factory=list)
    is_custom: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "system_prompt": self.system_prompt,
            "tool_acl": {
                "allowed": self.tool_acl.allowed,
                "forbidden": self.tool_acl.forbidden,
                "permission_required": self.tool_acl.permission_required,
                "auto_approve_seconds": self.tool_acl.auto_approve_seconds,
            },
            "workflow_template": self.workflow_template.to_list(),
            "learning_bias": self.learning_bias.value,
            "tool_filter_category": self.tool_filter_category,
            "is_custom": self.is_custom,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Persona:
        acl_data = data.get("tool_acl", {})
        acl = ToolACL(
            allowed=acl_data.get("allowed", ["*"]),
            forbidden=acl_data.get("forbidden", []),
            permission_required=acl_data.get("permission_required", []),
            auto_approve_seconds=acl_data.get("auto_approve_seconds", 10),
        )
        wf_data = data.get("workflow_template", [])
        wf = WorkflowTemplate(steps=list(wf_data) if isinstance(wf_data, list) else [])
        bias_str = data.get("learning_bias", "balanced")
        try:
            bias = LearningBias(bias_str)
        except ValueError:
            bias = LearningBias.BALANCED
        return cls(
            name=data.get("name", "unknown"),
            description=data.get("description", ""),
            system_prompt=data.get("system_prompt", ""),
            tool_acl=acl,
            workflow_template=wf,
            learning_bias=bias,
            tool_filter_category=data.get("tool_filter_category", []),
            is_custom=data.get("is_custom", False),
            metadata=data.get("metadata", {}),
        )


BUILTIN_PERSONAS: dict[str, Persona] = {
    PersonaName.OFFENSIVE: Persona(
        name="offensive",
        description="Offensive security operator - aggressive recon and exploitation",
        system_prompt=(
            "You are an offensive security operator conducting authorized penetration testing. "
            "Focus on aggressive reconnaissance, vulnerability discovery, and exploitation chaining. "
            "Prioritize high-impact findings and privilege escalation paths. "
            "Use the full attack toolkit with smart chaining of exploits."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=[],
            permission_required=["msfconsole", "msfvenom", "sqlmap", "meterpreter"],
            auto_approve_seconds=5,
        ),
        workflow_template=WorkflowTemplate(
            steps=["Reconnaissance", "Exploitation", "Post-Exploitation", "Reporting"]
        ),
        learning_bias=LearningBias.AGGRESSIVE,
        tool_filter_category=["recon", "exploitation", "post-exploitation"],
    ),
    PersonaName.DEFENSIVE: Persona(
        name="defensive",
        description="Defensive security analyst - monitoring and hardening",
        system_prompt=(
            "You are a defensive security analyst monitoring and hardening infrastructure. "
            "Focus on threat detection, log analysis, incident response, and security hardening. "
            "Prioritize safety and validation before any action. "
            "Use monitoring, hardening, and forensics tools."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=["msfconsole", "msfvenom", "sqlmap", "meterpreter"],
            permission_required=[],
            auto_approve_seconds=15,
        ),
        workflow_template=WorkflowTemplate(
            steps=["Detect", "Triage", "Contain", "Remediate"]
        ),
        learning_bias=LearningBias.CAUTIOUS,
        tool_filter_category=["monitoring", "hardening", "forensics"],
    ),
    PersonaName.BUG_HUNTER: Persona(
        name="bug_hunter",
        description="Bug bounty hunter - web and mobile application testing",
        system_prompt=(
            "You are a bug bounty hunter performing authorized security research. "
            "Focus on web application vulnerabilities, API testing, and responsible disclosure. "
            "Be methodical and document every finding with proof of concept. "
            "Respect scope boundaries strictly."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=["metasploit", "sqlmap"],
            permission_required=[],
            auto_approve_seconds=10,
        ),
        workflow_template=WorkflowTemplate(
            steps=[
                "Scope Validation",
                "Reconnaissance",
                "Testing",
                "Proof of Concept",
                "Report",
            ]
        ),
        learning_bias=LearningBias.METHODICAL,
        tool_filter_category=["web", "api", "recon"],
    ),
    PersonaName.PENTESTER: Persona(
        name="pentester",
        description="Penetration tester - full-scope security assessment",
        system_prompt=(
            "You are a penetration tester conducting a comprehensive security assessment. "
            "Follow industry-standard methodologies (PTES, OWASP, NIST). "
            "Document all evidence for compliance reporting. "
            "Be thorough and compliance-aware in all actions."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=[],
            permission_required=["msfconsole", "msfvenom", "meterpreter"],
            auto_approve_seconds=8,
        ),
        workflow_template=WorkflowTemplate(
            steps=["Planning", "Execution", "Evidence Collection", "Reporting"]
        ),
        learning_bias=LearningBias.METHODICAL,
        tool_filter_category=["recon", "web", "exploitation", "post-exploitation", "cloud"],
    ),
    PersonaName.SOC_ANALYST: Persona(
        name="soc_analyst",
        description="SOC analyst - incident detection and response",
        system_prompt=(
            "You are a SOC analyst monitoring for security incidents. "
            "Focus on alert triage, log analysis, threat hunting, and incident response. "
            "Be time-sensitive and prioritize critical alerts. "
            "Use SIEM, EDR, and forensics tools for investigation."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=[],
            permission_required=["volatility", "velociraptor"],
            auto_approve_seconds=5,
        ),
        workflow_template=WorkflowTemplate(
            steps=["Alert", "Investigate", "Escalate", "Resolve"]
        ),
        learning_bias=LearningBias.TIME_SENSITIVE,
        tool_filter_category=["forensics", "monitoring", "siem"],
    ),
    PersonaName.NONE: Persona(
        name="none",
        description="Universal security agent - no restrictions, context-dependent",
        system_prompt=(
            "You are a universal security agent with full toolkit access. "
            "Adapt to the task at hand and use judgment for tool selection. "
            "Balance offensive and defensive approaches based on context."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=[],
            permission_required=[],
            auto_approve_seconds=10,
        ),
        workflow_template=WorkflowTemplate(steps=["Context-dependent"]),
        learning_bias=LearningBias.BALANCED,
    ),
    PersonaName.AUTO: Persona(
        name="auto",
        description="Dynamic persona selection based on intent classification",
        system_prompt=(
            "You are an adaptive security agent. Your persona will be selected dynamically "
            "based on the intent of each task. Adapt your response style and tool selection "
            "to match the security domain detected in the user's request."
        ),
        tool_acl=ToolACL(
            allowed=["*"],
            forbidden=[],
            permission_required=[],
            auto_approve_seconds=10,
        ),
        workflow_template=WorkflowTemplate(steps=["Intent-classified"]),
        learning_bias=LearningBias.ADAPTIVE,
    ),
}

_INTENT_KEYWORDS: dict[str, tuple[str, float]] = {
    "vulnerab": (PersonaName.BUG_HUNTER, 0.87),
    "cve": (PersonaName.BUG_HUNTER, 0.85),
    "exploit": (PersonaName.OFFENSIVE, 0.9),
    "pentest": (PersonaName.PENTESTER, 0.92),
    "audit": (PersonaName.PENTESTER, 0.8),
    "compliance": (PersonaName.PENTESTER, 0.85),
    "alert": (PersonaName.SOC_ANALYST, 0.9),
    "incident": (PersonaName.SOC_ANALYST, 0.95),
    "investigat": (PersonaName.SOC_ANALYST, 0.88),
    "forensic": (PersonaName.SOC_ANALYST, 0.85),
    "monitor": (PersonaName.DEFENSIVE, 0.85),
    "harden": (PersonaName.DEFENSIVE, 0.82),
    "protect": (PersonaName.DEFENSIVE, 0.75),
    "defend": (PersonaName.DEFENSIVE, 0.8),
    "scan": (PersonaName.OFFENSIVE, 0.7),
    "recon": (PersonaName.OFFENSIVE, 0.8),
    "discover": (PersonaName.OFFENSIVE, 0.7),
    "bug bounty": (PersonaName.BUG_HUNTER, 0.95),
    "xss": (PersonaName.BUG_HUNTER, 0.9),
    "sql injection": (PersonaName.BUG_HUNTER, 0.9),
    "subdomain": (PersonaName.BUG_HUNTER, 0.75),
    "phish": (PersonaName.OFFENSIVE, 0.8),
    "malware": (PersonaName.SOC_ANALYST, 0.85),
    "ransomware": (PersonaName.SOC_ANALYST, 0.9),
    "ddos": (PersonaName.DEFENSIVE, 0.8),
    "firewall": (PersonaName.DEFENSIVE, 0.75),
    "cloud": (PersonaName.PENTESTER, 0.7),
    "aws": (PersonaName.PENTESTER, 0.75),
    "azure": (PersonaName.PENTESTER, 0.75),
    "gcp": (PersonaName.PENTESTER, 0.75),
    "kubernetes": (PersonaName.PENTESTER, 0.8),
    "k8s": (PersonaName.PENTESTER, 0.8),
    "docker": (PersonaName.PENTESTER, 0.7),
}


class PersonaEngine:
    """Core persona engine — manages personas, switching, and auto-detection."""

    def __init__(self, personas_dir: Path | None = None) -> None:
        self._personas_dir = personas_dir or _PERSONAS_DIR
        self._custom_dir = self._personas_dir / "custom"
        self._personas_dir.mkdir(parents=True, exist_ok=True)
        self._custom_dir.mkdir(parents=True, exist_ok=True)
        self._personas: dict[str, Persona] = {}
        self._active_persona: Persona | None = None
        self._load_all()

    def _load_all(self) -> None:
        """Load built-in personas."""
        self._personas = {}
        for name, persona in BUILTIN_PERSONAS.items():
            self._personas[name] = persona
        custom_personas = self._load_custom_personas()
        self._personas.update(custom_personas)

    def _load_custom_personas(self) -> dict[str, Persona]:
        """Load custom personas from disk."""
        custom: dict[str, Persona] = {}
        if not self._custom_dir.exists():
            return custom
        import yaml
        for path in self._custom_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "name" in data:
                    persona = Persona.from_dict(data)
                    persona.is_custom = True
                    custom[persona.name] = persona
            except Exception as exc:
                logger.warning("Failed to load custom persona %s: %s", path.name, exc)
        return custom

    def save_custom_persona(self, persona: Persona) -> Path:
        """Save a custom persona to disk."""
        persona.is_custom = True
        safe_name = persona.name.replace(" ", "_").lower()
        path = self._custom_dir / f"{safe_name}.yaml"
        try:
            import yaml
            path.write_text(yaml.dump(persona.to_dict(), default_flow_style=False), encoding="utf-8")
        except ImportError:
            import json
            path.write_text(json.dumps(persona.to_dict(), indent=2), encoding="utf-8")
        self._personas[persona.name] = persona
        return path

    @property
    def active_persona(self) -> Persona | None:
        return self._active_persona

    @property
    def persona_list(self) -> list[Persona]:
        """Return all available personas."""
        return list(self._personas.values())

    @property
    def persona_names(self) -> list[str]:
        """Return all persona names."""
        return list(self._personas.keys())

    def get_persona(self, name: str) -> Persona | None:
        """Get a persona by name."""
        return self._personas.get(name)

    def get_system_prompt(self, name: str | None = None) -> str:
        """Get the system prompt for a persona."""
        persona_name = name or (self._active_persona.name if self._active_persona else "none")
        persona = self._personas.get(persona_name)
        if not persona:
            persona = self._personas.get("none", BUILTIN_PERSONAS[PersonaName.NONE])
        return persona.system_prompt

    def switch_to(self, name: str) -> Persona:
        """Switch to a persona by name. Returns the persona."""
        start = time.monotonic()
        persona = self._personas.get(name)
        if not persona:
            raise ValueError(f"Unknown persona: {name}. Available: {list(self._personas.keys())}")
        self._active_persona = persona
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.debug("Persona switch to '%s' completed in %.1fms", name, elapsed_ms)
        return persona

    def classify_intent(self, instruction: str) -> tuple[str, float]:
        """Classify the intent of a natural language instruction to select best persona.

        Returns:
            Tuple of (persona_name, confidence_score).
        """
        instruction_lower = instruction.lower()
        scores: dict[str, float] = {}
        for keyword, (persona_name, base_score) in _INTENT_KEYWORDS.items():
            if keyword.lower() in instruction_lower:
                scores[persona_name] = max(scores.get(persona_name, 0), base_score)
        if scores:
            best = max(scores.items(), key=lambda x: x[1])
            return best
        return PersonaName.NONE, 0.0

    def detect_and_switch(self, instruction: str) -> Persona:
        """Auto-detect and switch persona based on instruction intent."""
        if self._active_persona and self._active_persona.name == PersonaName.AUTO:
            persona_name, confidence = self.classify_intent(instruction)
            if confidence >= 0.6:
                return self.switch_to(persona_name)
        return self._active_persona or self.switch_to(PersonaName.NONE)

    def get_filtered_tools(self, tools: list[str]) -> list[str]:
        """Filter tools based on active persona's ACL."""
        if not self._active_persona:
            return tools
        acl = self._active_persona.tool_acl
        return [t for t in tools if acl.is_allowed(t)]

    def get_workflow_template(self, name: str | None = None) -> list[str]:
        """Get the workflow template for a persona."""
        persona_name = name or (self._active_persona.name if self._active_persona else "none")
        persona = self._personas.get(persona_name)
        if not persona:
            return []
        return persona.workflow_template.to_list()


__all__ = [
    "PersonaEngine",
    "Persona",
    "PersonaName",
    "ToolACL",
    "WorkflowTemplate",
    "LearningBias",
    "BUILTIN_PERSONAS",
]
