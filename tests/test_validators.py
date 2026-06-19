from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.validators — input validation utilities."""


import pytest

from siyarix.exceptions import ValidationError
from siyarix.validators import (
    validate_hostname,
    validate_min_length,
    validate_not_empty,
    validate_target,
    validate_url,
)


class TestValidateNotEmpty:
    def test_valid(self) -> None:
        assert validate_not_empty("hello", "test") is None

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="test cannot be empty"):
            validate_not_empty("", "test")

    def test_whitespace_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_not_empty("   ", "test")


class TestValidateMinLength:
    def test_valid(self) -> None:
        assert validate_min_length("hello", 3, "test") is None

    def test_exact(self) -> None:
        assert validate_min_length("abc", 3, "test") is None

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValidationError, match="test must be at least 5 characters"):
            validate_min_length("ab", 5, "test")


class TestValidateHostname:
    def test_valid(self) -> None:
        assert validate_hostname("example.com") is None

    def test_with_port_stripped(self) -> None:
        assert validate_hostname("example.com:8080") is None

    def test_subdomain(self) -> None:
        assert validate_hostname("sub.example.com") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_hostname("-invalid-.com")


class TestValidateUrl:
    def test_valid_http(self) -> None:
        assert validate_url("http://example.com") is None

    def test_valid_https(self) -> None:
        assert validate_url("https://example.com/path?q=1") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("ftp://example.com")


class TestValidateTarget:
    def test_ipv4(self) -> None:
        result = validate_target("192.168.1.1")
        assert result == {"type": "ipv4", "normalized": "192.168.1.1"}

    def test_ipv6(self) -> None:
        result = validate_target("2001:db8::1")
        assert result["type"] == "ipv6"

    def test_cidr(self) -> None:
        result = validate_target("10.0.0.0/24")
        assert result["type"] == "cidr"

    def test_url(self) -> None:
        result = validate_target("https://example.com")
        assert result["type"] == "url"

    def test_hostname(self) -> None:
        result = validate_target("example.com")
        assert result["type"] == "hostname"

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid target"):
            validate_target("!!!invalid!!!")

    def test_empty_whitespace_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_target("   ")

    def test_strip_handles_whitespace(self) -> None:
        result = validate_target("  example.com  ")
        assert result["type"] == "hostname"
        assert result["normalized"] == "example.com"




"""Additional tests for siyarix.validators — covering uncovered functions and edge cases."""


import ipaddress
from unittest.mock import AsyncMock, patch


from siyarix.planner import PlanStep
from siyarix.validators import (
    RecoveryAction,
    RecoveryPlan,
    validate_cidr,
    validate_email,
    validate_port,
    validate_port_range,
    ValidationResult,
    ValidationSeverity,
    Validator,
    _enforce_length,
    _redact,
    _MAX_INPUT_LENGTH,
)


# ═══════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════

class TestEnforceLength:
    def test_under_limit_passes(self) -> None:
        _enforce_length("short", "test")  # should not raise

    def test_over_limit_raises(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            _enforce_length("a" * (_MAX_INPUT_LENGTH + 1), "target")

    def test_exact_limit_passes(self) -> None:
        _enforce_length("a" * _MAX_INPUT_LENGTH, "test")


class TestRedact:
    def test_short_value_returned_verbatim(self) -> None:
        assert _redact("short") == "short"

    def test_long_value_truncated(self) -> None:
        val = "a" * 100
        result = _redact(val)
        assert result.endswith("…[redacted]")
        assert len(result) < 100

    def test_exact_max_visible(self) -> None:
        val = "a" * 32
        assert _redact(val) == val

    def test_custom_max_visible(self) -> None:
        val = "a" * 50
        result = _redact(val, max_visible=10)
        assert result == "aaaaaaaaaa…[redacted]"

    def test_empty_string(self) -> None:
        assert _redact("") == ""


# ═══════════════════════════════════════════════════════════════════════════
# validate_not_empty (additional coverage)
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateNotEmptyAdditional:
    def test_whitespace_only_with_custom_field(self) -> None:
        with pytest.raises(ValidationError, match="query cannot be empty"):
            validate_not_empty("   ", "query")


# ═══════════════════════════════════════════════════════════════════════════
# validate_min_length (additional coverage)
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateMinLengthAdditional:
    def test_zero_min_len(self) -> None:
        validate_min_length("", 0)  # should pass

    def test_custom_field_name_in_message(self) -> None:
        with pytest.raises(ValidationError, match="password must be at least 8 characters"):
            validate_min_length("abc", 8, "password")


# ═══════════════════════════════════════════════════════════════════════════
# validate_hostname (additional coverage)
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateHostnameAdditional:
    def test_localhost(self) -> None:
        validate_hostname("localhost")  # passes (H-05)

    def test_single_label(self) -> None:
        validate_hostname("myserver")  # passes (H-05)

    def test_numeric_tld(self) -> None:
        validate_hostname("host.123")  # passes (H-05)

    def test_too_long_hostname(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_hostname("a" * 254)

    def test_too_long_overall_input(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_hostname("a" * (_MAX_INPUT_LENGTH + 1))

    def test_ip_looking_hostname_fails(self) -> None:
        # IP-like dotted quads are technically valid as hostnames
        # (each octet is a valid single-label). Ensure it at least doesn't
        # raise on the special-name "localhost".
        validate_hostname("192.168.1.1")  # passes; each quad is a valid label

    def test_hostname_with_port_stripped(self) -> None:
        validate_hostname("example.com:8080")  # passes; port stripped

    def test_hostname_multi_label(self) -> None:
        validate_hostname("sub.domain.example.com")  # passes

    def test_invalid_chars(self) -> None:
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_hostname("bad host!")

    def test_empty_string(self) -> None:
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_hostname("")


# ═══════════════════════════════════════════════════════════════════════════
# validate_url (additional coverage)
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateUrlAdditional:
    def test_url_with_path(self) -> None:
        validate_url("https://example.com/path/to/resource?q=1")

    def test_url_with_port(self) -> None:
        validate_url("http://example.com:8080/api")

    def test_bare_scheme_fails(self) -> None:
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("http://")

    def test_too_long_input(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_url("https://x.com/" + "a" * _MAX_INPUT_LENGTH)

    def test_no_scheme_fails(self) -> None:
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("example.com")

    def test_empty_string(self) -> None:
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("")


# ═══════════════════════════════════════════════════════════════════════════
# validate_port
# ═══════════════════════════════════════════════════════════════════════════

class TestValidatePort:
    def test_valid_int(self) -> None:
        assert validate_port(443) == 443

    def test_valid_string(self) -> None:
        assert validate_port("8080") == 8080

    def test_min_port(self) -> None:
        assert validate_port(1) == 1

    def test_max_port(self) -> None:
        assert validate_port(65535) == 65535

    def test_zero_raises(self) -> None:
        with pytest.raises(ValidationError, match="Port 0 out of range"):
            validate_port(0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError, match="Port -1 out of range"):
            validate_port(-1)

    def test_too_high_raises(self) -> None:
        with pytest.raises(ValidationError, match="Port 65536 out of range"):
            validate_port(65536)

    def test_non_numeric_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port("abc")

    def test_none_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port(None)  # type: ignore[arg-type]

    def test_float_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port("80.5")

    def test_float_int_is_truncated(self) -> None:
        # int(80.5) == 80, so this passes through validation
        assert validate_port(80.5) == 80


# ═══════════════════════════════════════════════════════════════════════════
# validate_port_range
# ═══════════════════════════════════════════════════════════════════════════

class TestValidatePortRange:
    def test_valid_range(self) -> None:
        assert validate_port_range("80-443") == (80, 443)

    def test_single_port(self) -> None:
        assert validate_port_range("8080") == (8080, 8080)

    def test_reversed_order_raises(self) -> None:
        with pytest.raises(ValidationError, match="Start port must be ≤ end port"):
            validate_port_range("443-80")

    def test_same_port(self) -> None:
        assert validate_port_range("80-80") == (80, 80)

    def test_out_of_range_start(self) -> None:
        with pytest.raises(ValidationError, match="Port 0 out of range"):
            validate_port_range("0-80")

    def test_out_of_range_end(self) -> None:
        with pytest.raises(ValidationError, match="Port 65536 out of range"):
            validate_port_range("80-65536")

    def test_invalid_format(self) -> None:
        with pytest.raises(ValidationError):
            validate_port_range("abc-def")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_port_range("a" * (_MAX_INPUT_LENGTH + 1))

    def test_whitespace_stripped(self) -> None:
        assert validate_port_range("  80-443  ") == (80, 443)


# ═══════════════════════════════════════════════════════════════════════════
# validate_cidr
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateCidr:
    def test_valid_ipv4_cidr(self) -> None:
        result = validate_cidr("10.0.0.0/24")
        assert isinstance(result, ipaddress.IPv4Network)
        assert str(result) == "10.0.0.0/24"

    def test_valid_ipv6_cidr(self) -> None:
        result = validate_cidr("fe80::/10")
        assert isinstance(result, ipaddress.IPv6Network)

    def test_invalid_cidr_pattern(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CIDR notation"):
            validate_cidr("not-cidr")

    def test_cidr_no_prefix_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CIDR notation"):
            validate_cidr("10.0.0.0")

    def test_invalid_prefix_length(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CIDR notation"):
            validate_cidr("10.0.0.0/33")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_cidr("a" * (_MAX_INPUT_LENGTH + 1))

    def test_whitespace_stripped(self) -> None:
        result = validate_cidr("  192.168.1.0/24  ")
        assert str(result) == "192.168.1.0/24"

    def test_host_bits_masked(self) -> None:
        result = validate_cidr("10.0.0.5/24")
        assert str(result) == "10.0.0.0/24"  # host bits masked due to strict=False


# ═══════════════════════════════════════════════════════════════════════════
# validate_email
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateEmail:
    def test_valid_email(self) -> None:
        validate_email("user@example.com")  # should pass

    def test_valid_email_subdomain(self) -> None:
        validate_email("user@sub.example.com")

    def test_email_with_plus(self) -> None:
        validate_email("user+tag@example.com")

    def test_no_at_sign_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email address"):
            validate_email("no-at-sign.com")

    def test_no_domain_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email address"):
            validate_email("user@")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_email("a" * (_MAX_INPUT_LENGTH + 1))

    def test_whitespace_stripped(self) -> None:
        validate_email("  user@example.com  ")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email address"):
            validate_email("")


# ═══════════════════════════════════════════════════════════════════════════
# validate_target (additional coverage)
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateTargetAdditional:
    def test_ipv6(self) -> None:
        result = validate_target("fe80::1")
        assert result["type"] == "ipv6"

    def test_cidr_no_slash_is_ip(self) -> None:
        result = validate_target("10.0.0.5")
        assert result["type"] == "ipv4"

    def test_url_with_path(self) -> None:
        result = validate_target("https://example.com/path?x=1")
        assert result["type"] == "url"

    def test_fallback_hostname(self) -> None:
        result = validate_target("my-server.local")
        assert result["type"] == "hostname"

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validate_target("x" * (_MAX_INPUT_LENGTH + 1))

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="target cannot be empty"):
            validate_target("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValidationError, match="target cannot be empty"):
            validate_target("   ")

    def test_completely_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid target format"):
            validate_target("!!!@#$%^^&*()")


# ═══════════════════════════════════════════════════════════════════════════
# ValidationSeverity / RecoveryAction / ValidationResult / RecoveryPlan
# ═══════════════════════════════════════════════════════════════════════════

class TestValidationSeverity:
    def test_values(self) -> None:
        assert ValidationSeverity.INFO == "info"
        assert ValidationSeverity.WARNING == "warning"
        assert ValidationSeverity.ERROR == "error"
        assert ValidationSeverity.CRITICAL == "critical"


class TestRecoveryAction:
    def test_values(self) -> None:
        assert RecoveryAction.RETRY == "retry"
        assert RecoveryAction.RETRY_ALTERNATIVE == "retry_alternative"
        assert RecoveryAction.SKIP == "skip"
        assert RecoveryAction.ABORT == "abort"
        assert RecoveryAction.ESCALATE == "escalate"
        assert RecoveryAction.DEGRADE == "degrade"


class TestValidationResult:
    def test_defaults(self) -> None:
        r = ValidationResult()
        assert r.passed is True
        assert r.severity == ValidationSeverity.INFO
        assert r.message == ""
        assert r.details == {}
        assert r.recovery_action is None
        assert r.recovery_suggestion == ""

    def test_custom(self) -> None:
        r = ValidationResult(
            passed=False,
            severity=ValidationSeverity.ERROR,
            message="fail",
            details={"key": "val"},
            recovery_action=RecoveryAction.SKIP,
            recovery_suggestion="skip it",
        )
        assert r.passed is False
        assert r.severity == ValidationSeverity.ERROR
        assert r.recovery_action == RecoveryAction.SKIP


class TestRecoveryPlan:
    def test_defaults(self) -> None:
        step = PlanStep(id="s1", tool="nmap")
        rp = RecoveryPlan(original_step=step, action=RecoveryAction.RETRY)
        assert rp.original_step is step
        assert rp.action == RecoveryAction.RETRY
        assert rp.modified_step is None
        assert rp.alternative_tool == ""
        assert rp.message == ""


# ═══════════════════════════════════════════════════════════════════════════
# Validator class
# ═══════════════════════════════════════════════════════════════════════════

class TestValidatorInit:
    def test_default_init(self) -> None:
        v = Validator()
        assert len(v._validators) == 3
        assert v._results == []


class TestValidatorValidateStepHasTool:
    def setup_method(self) -> None:
        self.v = Validator()

    def test_no_tool_fails(self) -> None:
        step = PlanStep(tool="")
        result = self.v._validate_step_has_tool(step)
        assert result.passed is False
        assert result.severity == ValidationSeverity.ERROR
        assert "no tool" in result.message
        assert result.recovery_action == RecoveryAction.SKIP

    def test_with_tool_passes(self) -> None:
        step = PlanStep(tool="nmap")
        result = self.v._validate_step_has_tool(step)
        assert result.passed is True


class TestValidatorValidateStepHasArgs:
    def setup_method(self) -> None:
        self.v = Validator()

    def test_no_args_and_not_report_summary_fails(self) -> None:
        step = PlanStep(tool="nmap", args={})
        result = self.v._validate_step_has_args(step)
        assert result.passed is False
        assert result.severity == ValidationSeverity.WARNING
        assert "no arguments" in result.message

    def test_no_args_for_report_passes(self) -> None:
        step = PlanStep(tool="report", args={})
        result = self.v._validate_step_has_args(step)
        assert result.passed is True

    def test_no_args_for_summary_passes(self) -> None:
        step = PlanStep(tool="summary", args={})
        result = self.v._validate_step_has_args(step)
        assert result.passed is True

    def test_with_args_passes(self) -> None:
        step = PlanStep(tool="nmap", args={"target": "10.0.0.1"})
        result = self.v._validate_step_has_args(step)
        assert result.passed is True


class TestValidatorValidateStepTimeout:
    def setup_method(self) -> None:
        self.v = Validator()

    def test_zero_timeout_fails(self) -> None:
        step = PlanStep(tool="nmap", timeout=0)
        result = self.v._validate_step_timeout(step)
        assert result.passed is False
        assert "non-positive" in result.message

    def test_negative_timeout_fails(self) -> None:
        step = PlanStep(tool="nmap", timeout=-5)
        result = self.v._validate_step_timeout(step)
        assert result.passed is False

    def test_positive_timeout_passes(self) -> None:
        step = PlanStep(tool="nmap", timeout=300)
        result = self.v._validate_step_timeout(step)
        assert result.passed is True


class TestValidatorValidateStep:
    def setup_method(self) -> None:
        self.v = Validator()

    async def test_all_validators_pass(self) -> None:
        step = PlanStep(tool="nmap", args={"target": "10.0.0.1"}, timeout=300)
        results = await self.v.validate_step(step)
        assert len(results) == 3
        assert all(r.passed for r in results)

    async def test_failure_emits_event(self) -> None:
        step = PlanStep(tool="", args={}, timeout=0)
        with patch.object(self.v._event_bus, "emit", AsyncMock()) as mock_emit:
            results = await self.v.validate_step(step)
            failed = [r for r in results if not r.passed]
            assert len(failed) > 0
            # The event bus should have been called for each failure
            assert mock_emit.await_count == len(failed)

    async def test_results_accumulated(self) -> None:
        step = PlanStep(tool="nmap", args={"target": "10.0.0.1"}, timeout=300)
        await self.v.validate_step(step)
        assert len(self.v._results) == 3

    async def test_tool_no_args_failure(self) -> None:
        step = PlanStep(tool="nmap", args={}, timeout=300)
        with patch.object(self.v._event_bus, "emit", AsyncMock()):
            results = await self.v.validate_step(step)
            assert not results[1].passed  # args validation failed


class TestValidatorValidatePlan:
    def setup_method(self) -> None:
        self.v = Validator()

    async def test_all_steps_validated(self) -> None:
        steps = [
            PlanStep(tool="nmap", args={"target": "10.0.0.1"}, timeout=300),
            PlanStep(tool="gobuster", args={"url": "http://example.com"}, timeout=300),
        ]
        results = await self.v.validate_plan(steps)
        assert len(results) == 6  # 3 validators * 2 steps

    async def test_empty_plan(self) -> None:
        results = await self.v.validate_plan([])
        assert results == []


class TestValidatorPlanRecovery:
    def setup_method(self) -> None:
        self.v = Validator()

    async def test_nmap_filtered_adds_pn(self) -> None:
        step = PlanStep(id="s1", description="scan", tool="nmap", args={"target": "10.0.0.1"})
        rp = await self.v.plan_recovery(step, "filtered")
        assert rp.action == RecoveryAction.RETRY
        assert rp.modified_step is not None
        assert " -Pn" in rp.modified_step.args.get("flags", "")

    async def test_nikto_refused_tries_nuclei(self) -> None:
        step = PlanStep(tool="nikto", args={"target": "10.0.0.1"})
        rp = await self.v.plan_recovery(step, "connection refused")
        assert rp.action == RecoveryAction.RETRY_ALTERNATIVE
        assert rp.alternative_tool == "nuclei"

    async def test_nuclei_refused_tries_nikto(self) -> None:
        step = PlanStep(tool="nuclei", args={"target": "10.0.0.1"})
        rp = await self.v.plan_recovery(step, "refused")
        assert rp.action == RecoveryAction.RETRY_ALTERNATIVE
        assert rp.alternative_tool == "nikto"

    async def test_gobuster_404_adds_extensions(self) -> None:
        step = PlanStep(
            id="s2", tool="gobuster", args={"url": "http://example.com"}, description="dirbust"
        )
        rp = await self.v.plan_recovery(step, "404")
        assert rp.action == RecoveryAction.RETRY
        assert "php" in rp.modified_step.args.get("extensions", "")

    async def test_ffuf_404_adds_extensions(self) -> None:
        step = PlanStep(
            id="s3", tool="ffuf", args={"url": "http://example.com"}, description="fuzz"
        )
        rp = await self.v.plan_recovery(step, "404")
        assert rp.action == RecoveryAction.RETRY
        assert "php" in rp.modified_step.args.get("extensions", "")

    async def test_can_retry(self) -> None:
        step = PlanStep(tool="nmap", retry_count=0, max_retries=3)
        rp = await self.v.plan_recovery(step, "error")
        assert rp.action == RecoveryAction.RETRY
        assert "Retrying" in rp.message

    async def test_max_retries_exceeded(self) -> None:
        step = PlanStep(tool="nmap", retry_count=3, max_retries=3)
        rp = await self.v.plan_recovery(step, "error")
        assert rp.action == RecoveryAction.SKIP
        assert "Max retries exceeded" in rp.message


class TestValidatorStats:
    def setup_method(self) -> None:
        self.v = Validator()

    def test_empty_stats(self) -> None:
        s = self.v.stats()
        assert s["total_validations"] == 0
        assert s["passed"] == 0
        assert s["failed"] == 0

    def test_stats_after_validations(self) -> None:
        self.v._results = [
            ValidationResult(passed=True),
            ValidationResult(passed=False),
            ValidationResult(passed=True),
        ]
        s = self.v.stats()
        assert s["total_validations"] == 3
        assert s["passed"] == 2
        assert s["failed"] == 1