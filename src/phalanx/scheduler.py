"""Phalanx Scan Scheduler — Persistent background cron and recurring scan coordinator."""

from __future__ import annotations

import os
import json
import time
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

SCHEDULES_FILE = Path.home() / ".phalanx" / "schedules.json"

@dataclass
class ScheduledJob:
    """A scheduled recurring scan job."""
    
    id: str
    name: str
    target: str
    cron: str  # standard interval: "daily", "weekly", "hourly", or standard 5-field cron
    command: str
    persona: str = "none"
    last_run: str = ""
    next_run: str = ""
    active: bool = True

    def calculate_next_run(self) -> datetime:
        """Simple next run calculation for intervals."""
        now = datetime.now(UTC)
        if self.cron == "hourly":
            return now + timedelta(hours=1)
        elif self.cron == "daily":
            return now + timedelta(days=1)
        elif self.cron == "weekly":
            return now + timedelta(weeks=1)
        else:
            # Fallback to daily
            return now + timedelta(days=1)


class PhalanxScheduler:
    """Persistent scan job scheduler and dispatcher."""

    def __init__(self, filepath: Path = SCHEDULES_FILE) -> None:
        self.filepath = filepath
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.jobs: Dict[str, ScheduledJob] = {}
        self.load()

    def load(self) -> None:
        """Load schedules from persistent storage."""
        if not self.filepath.exists():
            return
        try:
            data = json.loads(self.filepath.read_text(encoding="utf-8"))
            for jid, d in data.items():
                self.jobs[jid] = ScheduledJob(
                    id=jid,
                    name=d.get("name", ""),
                    target=d.get("target", ""),
                    cron=d.get("cron", "daily"),
                    command=d.get("command", ""),
                    persona=d.get("persona", "none"),
                    last_run=d.get("last_run", ""),
                    next_run=d.get("next_run", ""),
                    active=d.get("active", True),
                )
        except Exception as exc:
            logger.error("Error loading schedules: %s", exc)

    def save(self) -> None:
        """Save schedules to persistent storage."""
        try:
            data = {}
            for jid, job in self.jobs.items():
                data[jid] = {
                    "name": job.name,
                    "target": job.target,
                    "cron": job.cron,
                    "command": job.command,
                    "persona": job.persona,
                    "last_run": job.last_run,
                    "next_run": job.next_run,
                    "active": job.active,
                }
            self.filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Error saving schedules: %s", exc)

    def create(self, name: str, target: str, cron: str, command: str, persona: str = "none") -> ScheduledJob:
        """Create and schedule a new job."""
        jid = f"job_{str(uuid.uuid4())[:8]}" if "uuid" in globals() else f"job_{int(time.time())}"
        import uuid
        jid = f"job_{str(uuid.uuid4())[:8]}"
        
        job = ScheduledJob(
            id=jid,
            name=name,
            target=target,
            cron=cron,
            command=command,
            persona=persona,
            active=True,
        )
        job.next_run = job.calculate_next_run().isoformat()
        self.jobs[jid] = job
        self.save()
        return job

    def delete(self, jid_or_name: str) -> bool:
        """Delete a job by ID or Name."""
        target_id = None
        if jid_or_name in self.jobs:
            target_id = jid_or_name
        else:
            for jid, job in self.jobs.items():
                if job.name == jid_or_name:
                    target_id = jid
                    break
        if target_id:
            del self.jobs[target_id]
            self.save()
            return True
        return False

    def list_all(self) -> List[ScheduledJob]:
        """List all active and inactive schedules."""
        return list(self.jobs.values())

    async def execute_job(self, job: ScheduledJob) -> bool:
        """Execute the job immediately using the Phalanx Engine."""
        from phalanx.engine import ExecutionEngine
        from phalanx.audit_log import audit, AuditEventType, AuditSeverity
        
        logger.info("Executing scheduled job %s: %s", job.name, job.command)
        job.last_run = datetime.now(UTC).isoformat()
        job.next_run = job.calculate_next_run().isoformat()
        self.save()

        audit.log(
            event_type=AuditEventType.SCAN_START,
            severity=AuditSeverity.INFO,
            user="scheduler",
            action="scheduled_scan",
            result="started",
            target=job.target,
            details={"job_name": job.name, "command": job.command, "persona": job.persona},
        )

        try:
            engine = ExecutionEngine()
            result = await engine.execute(job.command, interactive=False, persist=True)
            
            audit.log(
                event_type=AuditEventType.SCAN_COMPLETE,
                severity=AuditSeverity.INFO,
                user="scheduler",
                action="scheduled_scan",
                result="success" if result.success else "failed",
                target=job.target,
                details={"job_name": job.name, "findings": len(result.all_findings)},
            )
            return result.success
        except Exception as exc:
            logger.error("Error executing job %s: %s", job.name, exc)
            return False


scheduler_service = PhalanxScheduler()
