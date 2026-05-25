"""Playbook engine for saving and replaying multi-step workflows.

Enables users to create, save, load, and execute reusable workflow
playbooks with variables, conditionals, loops, and error handling
as described in Chapter 17.1.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PlaybookStepType(str, Enum):
    COMMAND = "command"
    PLAYBOOK = "playbook"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    DELAY = "delay"
    PROMPT = "prompt"
    EXPORT = "export"


@dataclass
class PlaybookStep:
    """A single step within a playbook."""

    name: str = ""
    step_type: PlaybookStepType = PlaybookStepType.COMMAND
    command: str = ""
    variables: dict[str, str] = field(default_factory=dict)
    condition: str = ""
    loop_over: str = ""
    loop_var: str = "item"
    on_error: str = "abort"  # abort | skip | retry
    max_retries: int = 1
    timeout_seconds: int = 300
    depends_on: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Playbook:
    """A reusable workflow playbook."""

    name: str = ""
    description: str = ""
    version: str = "1.0"
    author: str = "Phalanx User"
    variables: dict[str, str] = field(default_factory=dict)
    steps: list[PlaybookStep] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def resolve_variables(self, command: str, extra_vars: dict[str, str] | None = None) -> str:
        vars_map = dict(self.variables)
        if extra_vars:
            vars_map.update(extra_vars)
        for key, value in vars_map.items():
            command = command.replace(f"{{{key}}}", value)
        return command


class PlaybookEngine:
    """Engine for managing and executing playbooks."""

    PLAYBOOKS_DIR = Path.home() / ".phalanx" / "playbooks"

    def __init__(self, playbooks_dir: Path | None = None) -> None:
        self._dir = playbooks_dir or self.PLAYBOOKS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._loaded: dict[str, Playbook] = {}

    def save(self, playbook: Playbook) -> Path:
        path = self._dir / f"{playbook.name}.json"
        data = {
            "name": playbook.name,
            "description": playbook.description,
            "version": playbook.version,
            "author": playbook.author,
            "variables": playbook.variables,
            "steps": [
                {
                    "name": s.name,
                    "step_type": s.step_type.value,
                    "command": s.command,
                    "variables": s.variables,
                    "condition": s.condition,
                    "loop_over": s.loop_over,
                    "loop_var": s.loop_var,
                    "on_error": s.on_error,
                    "max_retries": s.max_retries,
                    "timeout_seconds": s.timeout_seconds,
                    "depends_on": s.depends_on,
                    "description": s.description,
                }
                for s in playbook.steps
            ],
            "tags": playbook.tags,
            "created_at": playbook.created_at,
            "updated_at": datetime.now().isoformat(),
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._loaded[playbook.name] = playbook
        logger.info("Playbook '%s' saved to %s", playbook.name, path)
        return path

    def load(self, name: str) -> Playbook | None:
        if name in self._loaded:
            return self._loaded[name]

        path = self._dir / f"{name}.json"
        if not path.exists():
            logger.warning("Playbook '%s' not found at %s", name, path)
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            playbook = Playbook(
                name=data["name"],
                description=data.get("description", ""),
                version=data.get("version", "1.0"),
                author=data.get("author", "Phalanx User"),
                variables=data.get("variables", {}),
                steps=[
                    PlaybookStep(
                        name=s.get("name", f"step-{i}"),
                        step_type=PlaybookStepType(s.get("step_type", "command")),
                        command=s.get("command", ""),
                        variables=s.get("variables", {}),
                        condition=s.get("condition", ""),
                        loop_over=s.get("loop_over", ""),
                        loop_var=s.get("loop_var", "item"),
                        on_error=s.get("on_error", "abort"),
                        max_retries=s.get("max_retries", 1),
                        timeout_seconds=s.get("timeout_seconds", 300),
                        depends_on=s.get("depends_on", []),
                        description=s.get("description", ""),
                    )
                    for i, s in enumerate(data.get("steps", []))
                ],
                tags=data.get("tags", []),
                created_at=data.get("created_at", ""),
                updated_at=data.get("updated_at", ""),
            )
            self._loaded[name] = playbook
            return playbook
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Failed to load playbook '%s': %s", name, exc)
            return None

    def list_playbooks(self) -> list[dict[str, Any]]:
        playbooks: list[dict[str, Any]] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                playbooks.append(
                    {
                        "name": data.get("name", path.stem),
                        "description": data.get("description", ""),
                        "step_count": len(data.get("steps", [])),
                        "tags": data.get("tags", []),
                        "updated_at": data.get("updated_at", ""),
                    }
                )
            except json.JSONDecodeError:
                continue
        return playbooks

    def delete(self, name: str) -> bool:
        self._loaded.pop(name, None)
        path = self._dir / f"{name}.json"
        if path.exists():
            path.unlink()
            logger.info("Playbook '%s' deleted", name)
            return True
        return False

    def create_bugbounty_recon(self) -> Playbook:
        playbook = Playbook(
            name="bugbounty-recon",
            description="Standard bug bounty reconnaissance workflow",
            author="Phalanx Built-in",
            variables={"target": "", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
            tags=["recon", "bugbounty", "web"],
        )
        playbook.steps = [
            PlaybookStep(
                name="subdomain-enum",
                command="subfinder -d {target} -o subs.txt",
                description="Enumerate subdomains",
                timeout_seconds=120,
            ),
            PlaybookStep(
                name="live-check",
                command="cat subs.txt | httpx -o live.txt",
                description="Check which subdomains are live",
                depends_on=["subdomain-enum"],
                timeout_seconds=60,
            ),
            PlaybookStep(
                name="port-scan",
                command="nmap -sV -iL live.txt -oA nmap-scan",
                description="Service version detection on live hosts",
                depends_on=["live-check"],
                timeout_seconds=300,
            ),
            PlaybookStep(
                name="vuln-scan",
                command="nuclei -l live.txt -t cves/ -severity critical,high -o nuclei-results.txt",
                description="Vulnerability scan with Nuclei CVE templates",
                depends_on=["live-check"],
                timeout_seconds=300,
            ),
            PlaybookStep(
                name="dir-bust",
                command="gobuster dir -u http://{target} -w {wordlist} -o dirs.txt",
                description="Directory brute-force",
                timeout_seconds=180,
            ),
            PlaybookStep(
                name="generate-report",
                command="phalanx report generate --findings nuclei-results.txt",
                description="Generate findings report",
                depends_on=["vuln-scan", "dir-bust"],
            ),
        ]
        return playbook

    def create_incident_response(self) -> Playbook:
        playbook = Playbook(
            name="incident-response",
            description="Standard incident response workflow",
            author="Phalanx Built-in",
            variables={"target": "", "evidence_type": "memory"},
            tags=["ir", "dfir", "forensics"],
        )
        playbook.steps = [
            PlaybookStep(
                name="collect-evidence",
                command="dfir-collect --target {target} --type {evidence_type}",
                description="Collect forensic evidence",
                timeout_seconds=600,
            ),
            PlaybookStep(
                name="analyze-memory",
                command="volatility -f memory.dump windows.pslist",
                description="Analyze memory for suspicious processes",
                depends_on=["collect-evidence"],
                timeout_seconds=120,
            ),
            PlaybookStep(
                name="extract-iocs",
                command="ioc-extract --input memory.dump --output iocs.json",
                description="Extract Indicators of Compromise",
                depends_on=["analyze-memory"],
                timeout_seconds=60,
            ),
            PlaybookStep(
                name="generate-timeline",
                command="timeline-generate --evidence collected/",
                description="Generate incident timeline",
                depends_on=["collect-evidence"],
                timeout_seconds=30,
            ),
            PlaybookStep(
                name="report",
                command="phalanx report generate --iocs iocs.json --timeline timeline.json",
                description="Generate incident report",
                depends_on=["extract-iocs", "generate-timeline"],
            ),
        ]
        return playbook

    def get_builtin_playbooks(self) -> list[Playbook]:
        return [self.create_bugbounty_recon(), self.create_incident_response()]

    def install_builtins(self) -> list[str]:
        installed = []
        for playbook in self.get_builtin_playbooks():
            self.save(playbook)
            installed.append(playbook.name)
        return installed


__all__ = ["PlaybookEngine", "Playbook", "PlaybookStep", "PlaybookStepType"]
