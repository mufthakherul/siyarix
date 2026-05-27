from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.scheduler import ScheduledJob, SiyarixScheduler


@pytest.fixture
def schedules_file(tmp_path: Path) -> Path:
    return tmp_path / ".siyarix" / "schedules.json"


@pytest.fixture
def scheduler(schedules_file: Path) -> SiyarixScheduler:
    return SiyarixScheduler(filepath=schedules_file)


class TestScheduledJob:
    def test_calculate_next_run_hourly(self) -> None:
        job = ScheduledJob(id="j1", name="", target="", cron="hourly", command="")
        next_run = job.calculate_next_run()
        assert next_run is not None

    def test_calculate_next_run_daily(self) -> None:
        job = ScheduledJob(id="j1", name="", target="", cron="daily", command="")
        next_run = job.calculate_next_run()
        assert next_run is not None

    def test_calculate_next_run_weekly(self) -> None:
        job = ScheduledJob(id="j1", name="", target="", cron="weekly", command="")
        next_run = job.calculate_next_run()
        assert next_run is not None

    def test_calculate_next_run_fallback(self) -> None:
        job = ScheduledJob(id="j1", name="", target="", cron="monthly", command="")
        next_run = job.calculate_next_run()
        assert next_run is not None

    def test_job_defaults(self) -> None:
        job = ScheduledJob(id="j1", name="test", target="t", cron="daily", command="cmd")
        assert job.persona == "none"
        assert job.last_run == ""
        assert job.next_run == ""
        assert job.active is True


class TestSiyarixScheduler:
    def test_init_creates_directory(self, schedules_file: Path) -> None:
        assert not schedules_file.parent.exists()
        SiyarixScheduler(filepath=schedules_file)
        assert schedules_file.parent.exists()

    def test_init_loads_existing(self, schedules_file: Path) -> None:
        schedules_file.parent.mkdir(parents=True, exist_ok=True)
        data = {"job_x": {"name": "X", "target": "t", "cron": "daily", "command": "c", "active": True}}
        schedules_file.write_text(json.dumps(data))
        s = SiyarixScheduler(filepath=schedules_file)
        assert "job_x" in s.jobs
        assert s.jobs["job_x"].name == "X"

    def test_load_file_not_exists(self, scheduler: SiyarixScheduler) -> None:
        assert scheduler.filepath.exists() is False
        scheduler.load()
        assert len(scheduler.jobs) == 0

    def test_load_corrupted_json(self, scheduler: SiyarixScheduler) -> None:
        scheduler.filepath.parent.mkdir(parents=True, exist_ok=True)
        scheduler.filepath.write_text("not json")
        with patch("siyarix.scheduler.logger") as mock_log:
            scheduler.load()
            mock_log.error.assert_called_once()

    def test_save_and_reload(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("Test", "10.0.0.1", "daily", "nmap -sV")
        scheduler.save()
        assert scheduler.filepath.exists()
        data = json.loads(scheduler.filepath.read_text())
        assert job.id in data

    def test_save_error(self, scheduler: SiyarixScheduler) -> None:
        with patch("siyarix.scheduler.json.dumps", side_effect=PermissionError("denied")):
            scheduler.create("Test", "t", "daily", "c")
            with patch("siyarix.scheduler.logger") as mock_log:
                scheduler.save()
                mock_log.error.assert_called()

    def test_create_job(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("Nightly Scan", "10.0.0.2", "daily", "nuclei -u $target", persona="scanner")
        assert job.name == "Nightly Scan"
        assert job.target == "10.0.0.2"
        assert job.cron == "daily"
        assert job.command == "nuclei -u $target"
        assert job.persona == "scanner"
        assert job.active is True
        assert job.id in scheduler.jobs
        assert job.next_run != ""

    def test_create_job_default_persona(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("Simple", "t", "hourly", "cmd")
        assert job.persona == "none"

    def test_delete_by_id(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("Test", "t", "daily", "c")
        assert scheduler.delete(job.id) is True
        assert job.id not in scheduler.jobs

    def test_delete_by_name(self, scheduler: SiyarixScheduler) -> None:
        scheduler.create("TestJob", "t", "daily", "c")
        assert scheduler.delete("TestJob") is True
        assert len(scheduler.jobs) == 0

    def test_delete_not_found(self, scheduler: SiyarixScheduler) -> None:
        assert scheduler.delete("nonexistent") is False

    def test_list_all_empty(self, scheduler: SiyarixScheduler) -> None:
        assert scheduler.list_all() == []

    def test_list_all_with_jobs(self, scheduler: SiyarixScheduler) -> None:
        j1 = scheduler.create("A", "t1", "daily", "c1")
        j2 = scheduler.create("B", "t2", "daily", "c2")
        jobs = scheduler.list_all()
        assert len(jobs) == 2
        assert j1 in jobs
        assert j2 in jobs

    @pytest.mark.asyncio
    async def test_execute_job_success(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("ExecTest", "10.0.0.3", "daily", "nmap -sV")
        mock_engine = AsyncMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.all_findings = []
        mock_engine.execute.return_value = mock_result

        with (
            patch("siyarix.engine.ExecutionEngine", return_value=mock_engine),
            patch("siyarix.audit_log.audit") as mock_audit,
        ):
            result = await scheduler.execute_job(job)

        assert result is True
        assert mock_engine.execute.call_count == 1
        assert mock_audit.log.call_count == 2

    @pytest.mark.asyncio
    async def test_execute_job_failure(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("FailTest", "10.0.0.4", "daily", "bad-command")
        mock_engine = AsyncMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.all_findings = []
        mock_engine.execute.return_value = mock_result

        with (
            patch("siyarix.engine.ExecutionEngine", return_value=mock_engine),
            patch("siyarix.audit_log.audit"),
        ):
            result = await scheduler.execute_job(job)

        assert result is False

    @pytest.mark.asyncio
    async def test_execute_job_exception(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("ExcepTest", "10.0.0.5", "daily", "crash")
        mock_engine = AsyncMock()
        mock_engine.execute.side_effect = RuntimeError("Engine crash")

        with (
            patch("siyarix.engine.ExecutionEngine", return_value=mock_engine),
            patch("siyarix.scheduler.logger") as mock_log,
            patch("siyarix.audit_log.audit"),
        ):
            result = await scheduler.execute_job(job)

        assert result is False
        mock_log.error.assert_called_once()

    def test_delete_saves(self, scheduler: SiyarixScheduler) -> None:
        job = scheduler.create("SaveTest", "t", "daily", "c")
        assert scheduler.filepath.exists()
        scheduler.delete(job.id)
        reloaded = json.loads(scheduler.filepath.read_text())
        assert job.id not in reloaded

    def test_create_generates_unique_id(self, scheduler: SiyarixScheduler) -> None:
        j1 = scheduler.create("A", "t", "daily", "c")
        j2 = scheduler.create("B", "t", "daily", "c")
        assert j1.id != j2.id
