"""Session logging — structured session logs per Chapter 11 spec.

Provides SessionLog dataclass matching the spec JSON schema and
SessionLogger manager for persistence, listing, and export.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SIYARIX_DIR = Path(os.getenv("SIYARIX_CONFIG_DIR", str(Path.home() / ".siyarix")))
_LOG_DIR = _SIYARIX_DIR / "logs"


@dataclass
class SafetyEvent:
    type: str = "permission_gate"
    command: str = ""
    action: str = ""


@dataclass
class CommandEntry:
    id: int = 0
    timestamp: str = ""
    input: str = ""
    masked_input: str = ""
    ai_plan: list[str] = field(default_factory=list)
    approved: bool = True
    execution_time_ms: float = 0.0
    output_summary: str = ""
    full_output_ref: str = ""


@dataclass
class SessionLog:
    session_id: str = ""
    timestamp_start: str = ""
    timestamp_end: str = ""
    persona: str = ""
    llm_provider: str = ""
    llm_model: str = ""
    user: str = ""
    commands: list[CommandEntry] = field(default_factory=list)
    tool_usage: dict[str, int] = field(default_factory=dict)
    safety_events: list[SafetyEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "persona": self.persona,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "user": self.user,
            "commands": [asdict(c) for c in self.commands],
            "tool_usage": dict(self.tool_usage),
            "safety_events": [asdict(s) for s in self.safety_events],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionLog:
        commands = [CommandEntry(**c) for c in data.get("commands", [])]
        safety = [SafetyEvent(**s) for s in data.get("safety_events", [])]
        return cls(
            session_id=data.get("session_id", ""),
            timestamp_start=data.get("timestamp_start", ""),
            timestamp_end=data.get("timestamp_end", ""),
            persona=data.get("persona", ""),
            llm_provider=data.get("llm_provider", ""),
            llm_model=data.get("llm_model", ""),
            user=data.get("user", ""),
            commands=commands,
            tool_usage=data.get("tool_usage", {}),
            safety_events=safety,
        )


class SessionLogger:
    """Manages session logs with JSON persistence."""

    def __init__(self, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or _LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        return self._log_dir / f"{session_id}.json"

    def save(self, log: SessionLog) -> Path:
        path = self._path(log.session_id)
        path.write_text(
            json.dumps(log.to_dict(), indent=2, default=str), encoding="utf-8"
        )
        return path

    def load(self, session_id: str) -> SessionLog | None:
        path = self._path(session_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return SessionLog.from_dict(data)
        except Exception as exc:
            logger.warning("Failed to load session log %s: %s", session_id, exc)
            return None

    def list_logs(self) -> list[dict[str, Any]]:
        if not self._log_dir.exists():
            return []
        logs: list[dict[str, Any]] = []
        for path in sorted(
            self._log_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        ):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                logs.append(
                    {
                        "session_id": data.get("session_id", path.stem),
                        "timestamp_start": data.get("timestamp_start", ""),
                        "timestamp_end": data.get("timestamp_end", ""),
                        "persona": data.get("persona", ""),
                        "llm_provider": data.get("llm_provider", ""),
                        "commands": len(data.get("commands", [])),
                        "tool_count": len(data.get("tool_usage", {})),
                        "safety_events": len(data.get("safety_events", [])),
                    }
                )
            except Exception as exc:
                logger.warning("Failed to parse session log %s: %s", path, exc)
                continue
        return logs

    def delete(self, session_id: str) -> bool:
        path = self._path(session_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def export_markdown(self, session_id: str) -> str | None:
        log = self.load(session_id)
        if not log:
            return None
        lines = [
            f"# Session Log: {log.session_id}",
            "",
            f"**Start:** {log.timestamp_start}  ",
            f"**End:** {log.timestamp_end}  ",
            f"**Persona:** {log.persona}  ",
            f"**LLM:** {log.llm_provider}/{log.llm_model}  ",
            f"**User:** {log.user}  ",
            "",
            "## Tool Usage",
            "",
        ]
        for tool, count in sorted(log.tool_usage.items()):
            lines.append(f"- **{tool}**: {count} call(s)")
        lines.append("")
        if log.safety_events:
            lines.extend(["## Safety Events", ""])
            for ev in log.safety_events:
                lines.append(f"- `{ev.type}` | `{ev.command}` → {ev.action}")
            lines.append("")
        if log.commands:
            lines.extend(["## Commands", ""])
            for cmd in log.commands:
                lines.append(f"### Command #{cmd.id}")
                lines.append(f"- **Input:** `{cmd.input}`")
                if cmd.masked_input:
                    lines.append(f"- **Masked:** `{cmd.masked_input}`")
                if cmd.ai_plan:
                    lines.append(f"- **AI Plan:** `{'` → `'.join(cmd.ai_plan)}`")
                lines.append(f"- **Approved:** {cmd.approved}")
                lines.append(f"- **Time:** {cmd.execution_time_ms}ms")
                lines.append(f"- **Output:** {cmd.output_summary}")
                if cmd.full_output_ref:
                    lines.append(f"- **Full Output:** `{cmd.full_output_ref}`")
                lines.append("")
        return "\n".join(lines)

    def export_json_str(self, session_id: str) -> str | None:
        log = self.load(session_id)
        if not log:
            return None
        return json.dumps(log.to_dict(), indent=2, default=str)

    def export_sarif(self, session_id: str) -> str | None:
        log = self.load(session_id)
        if not log:
            return None
        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Siyarix",
                            "version": log.llm_provider or "unknown",
                            "informationUri": "https://siyarix.ai",
                        }
                    },
                    "invocations": [
                        {
                            "startTimeUtc": log.timestamp_start,
                            "endTimeUtc": log.timestamp_end,
                        }
                    ],
                    "results": [],
                }
            ],
        }
        for cmd in log.commands:
            sarif["runs"][0]["results"].append(
                {
                    "message": {"text": cmd.input},
                    "ruleId": f"CMD-{cmd.id:04d}",
                }
            )
        return json.dumps(sarif, indent=2, default=str)

    def add_safety_event(self, session_id: str, command: str, action: str) -> bool:
        log = self.load(session_id)
        if not log:
            return False
        log.safety_events.append(SafetyEvent(command=command, action=action))
        self.save(log)
        return True

    def add_command(
        self,
        session_id: str,
        input_text: str,
        masked_input: str = "",
        ai_plan: list[str] | None = None,
        approved: bool = True,
        execution_time_ms: float = 0.0,
        output_summary: str = "",
    ) -> bool:
        log = self.load(session_id)
        if not log:
            return False
        cmd_id = len(log.commands) + 1
        ref = f"logs/{session_id}/cmd_{cmd_id:02d}_output.txt"
        log.commands.append(
            CommandEntry(
                id=cmd_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                input=input_text,
                masked_input=masked_input,
                ai_plan=ai_plan or [],
                approved=approved,
                execution_time_ms=execution_time_ms,
                output_summary=output_summary,
                full_output_ref=ref,
            )
        )
        self.save(log)
        return True

    def track_tool_usage(self, session_id: str, tool: str, count: int = 1) -> bool:
        log = self.load(session_id)
        if not log:
            return False
        log.tool_usage[tool] = log.tool_usage.get(tool, 0) + count
        self.save(log)
        return True

    def update_end_time(self, session_id: str) -> bool:
        log = self.load(session_id)
        if not log:
            return False
        log.timestamp_end = datetime.now(timezone.utc).isoformat()
        self.save(log)
        return True

    def create_log(
        self,
        session_id: str,
        persona: str = "",
        llm_provider: str = "",
        llm_model: str = "",
        user: str = "",
    ) -> SessionLog:
        log = SessionLog(
            session_id=session_id,
            timestamp_start=datetime.now(timezone.utc).isoformat(),
            timestamp_end="",
            persona=persona,
            llm_provider=llm_provider,
            llm_model=llm_model,
            user=user,
        )
        self.save(log)
        return log


session_logger = SessionLogger()

__all__ = [
    "SessionLog",
    "CommandEntry",
    "SafetyEvent",
    "SessionLogger",
    "session_logger",
]
