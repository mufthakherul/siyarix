"""Tests for siyarix.exceptions - Custom exception hierarchy."""

from __future__ import annotations

from siyarix.exceptions import (
    BudgetExceededError,
    ConfigError,
    CredentialError,
    ErrorContext,
    ErrorSeverity,
    LLMProviderError,
    PermissionDeniedError,
    SiyarixException,
    ToolExecutionError,
    ToolNotFoundError,
    ValidationError,
    exit_code_for,
)


class TestErrorSeverity:
    def test_values(self):
        assert ErrorSeverity.CRITICAL == "critical"
        assert ErrorSeverity.ERROR == "error"
        assert ErrorSeverity.WARNING == "warning"
        assert ErrorSeverity.INFO == "info"

    def test_members(self):
        assert len(ErrorSeverity) == 4


class TestErrorContext:
    def test_defaults(self):
        ctx = ErrorContext()
        assert ctx.severity == ErrorSeverity.ERROR
        assert ctx.user_message == ""
        assert ctx.technical_details is None
        assert ctx.suggestions is None
        assert ctx.component == ""

    def test_custom(self):
        ctx = ErrorContext(
            severity=ErrorSeverity.CRITICAL,
            user_message="Something broke",
            technical_details={"code": 500},
            suggestions=["Restart the service"],
            component="auth",
        )
        assert ctx.severity == ErrorSeverity.CRITICAL
        assert ctx.user_message == "Something broke"
        assert ctx.technical_details == {"code": 500}
        assert ctx.suggestions == ["Restart the service"]
        assert ctx.component == "auth"


class TestSiyarixException:
    def test_basic_message(self):
        exc = SiyarixException("test error")
        assert exc.message == "test error"
        assert exc.context.severity == ErrorSeverity.ERROR
        assert exc.cause is None
        assert str(exc) == "test error"

    def test_with_context(self):
        ctx = ErrorContext(
            severity=ErrorSeverity.WARNING,
            user_message="User message",
            component="test",
            technical_details={"key": "val"},
            suggestions=["try this", "try that"],
        )
        exc = SiyarixException("main error", context=ctx)
        msg = str(exc)
        assert "[test]" in msg
        assert "main error" in msg
        assert "User message" in msg
        assert "key" in msg
        assert "try this" in msg
        assert "try that" in msg

    def test_with_cause(self):
        cause = ValueError("original")
        exc = SiyarixException("wrapped error", cause=cause)
        assert exc.cause is cause

    def test_component_in_message(self):
        ctx = ErrorContext(component="network")
        exc = SiyarixException("timeout", context=ctx)
        assert "[network] timeout" == str(exc)

    def test_user_message_in_message(self):
        ctx = ErrorContext(user_message="Please check your input")
        exc = SiyarixException("validation failed", context=ctx)
        msg = str(exc)
        assert "validation failed" in msg
        assert "Please check your input" in msg

    def test_technical_details_in_message(self):
        ctx = ErrorContext(technical_details={"host": "10.0.0.1"})
        exc = SiyarixException("connection error", context=ctx)
        assert "host" in str(exc)

    def test_suggestions_in_message(self):
        ctx = ErrorContext(suggestions=["Check firewall", "Verify port"])
        exc = SiyarixException("cannot connect", context=ctx)
        msg = str(exc)
        assert "Check firewall" in msg
        assert "Verify port" in msg

    def test_full_message(self):
        ctx = ErrorContext(
            component="scanner",
            user_message="Check your target",
            technical_details={"target": "10.0.0.1"},
            suggestions=["Try a different target", "Check permissions"],
        )
        exc = SiyarixException("Scan failed", context=ctx)
        msg = str(exc)
        assert "[scanner] Scan failed" in msg
        assert "Check your target" in msg
        assert "target" in msg
        assert "Try a different target" in msg
        assert "Check permissions" in msg

    def test_is_exception(self):
        exc = SiyarixException("test")
        assert isinstance(exc, Exception)

    def test_raise_and_catch(self):
        with pytest.raises(SiyarixException) as excinfo:
            raise SiyarixException("raise test")
        assert str(excinfo.value) == "raise test"


class TestSubclassInheritance:
    def test_validation_error(self):
        assert issubclass(ValidationError, SiyarixException)

    def test_budget_exceeded(self):
        assert issubclass(BudgetExceededError, SiyarixException)

    def test_permission_denied(self):
        assert issubclass(PermissionDeniedError, SiyarixException)

    def test_tool_not_found(self):
        assert issubclass(ToolNotFoundError, SiyarixException)

    def test_tool_execution_error(self):
        assert issubclass(ToolExecutionError, SiyarixException)

    def test_llm_provider_error(self):
        assert issubclass(LLMProviderError, SiyarixException)

    def test_config_error(self):
        assert issubclass(ConfigError, SiyarixException)

    def test_credential_error(self):
        assert issubclass(CredentialError, SiyarixException)

    def test_all_subclasses_of_siyarix(self):
        exceptions = [
            ValidationError,
            BudgetExceededError,
            PermissionDeniedError,
            ToolNotFoundError,
            ToolExecutionError,
            LLMProviderError,
            ConfigError,
            CredentialError,
        ]
        for exc_cls in exceptions:
            assert isinstance(exc_cls("test"), SiyarixException)

    def test_all_subclasses_of_exception(self):
        exceptions = [
            ValidationError,
            BudgetExceededError,
            PermissionDeniedError,
            ToolNotFoundError,
            ToolExecutionError,
            LLMProviderError,
            ConfigError,
            CredentialError,
        ]
        for exc_cls in exceptions:
            assert isinstance(exc_cls("test"), Exception)


class TestConcreteExceptions:
    def test_validation_error_raise(self):
        with pytest.raises(ValidationError) as excinfo:
            raise ValidationError("invalid input")
        assert str(excinfo.value) == "invalid input"

    def test_validation_error_with_context(self):
        ctx = ErrorContext(component="input")
        exc = ValidationError("bad data", context=ctx)
        assert "[input] bad data" in str(exc)

    def test_budget_exceeded(self):
        with pytest.raises(BudgetExceededError):
            raise BudgetExceededError("budget exceeded")

    def test_permission_denied(self):
        with pytest.raises(PermissionDeniedError):
            raise PermissionDeniedError("access denied")

    def test_tool_not_found(self):
        with pytest.raises(ToolNotFoundError):
            raise ToolNotFoundError("nmap not found")

    def test_tool_execution_error(self):
        with pytest.raises(ToolExecutionError):
            raise ToolExecutionError("execution failed")

    def test_llm_provider_error(self):
        with pytest.raises(LLMProviderError):
            raise LLMProviderError("provider timeout")

    def test_config_error(self):
        with pytest.raises(ConfigError):
            raise ConfigError("missing config")

    def test_credential_error(self):
        with pytest.raises(CredentialError):
            raise CredentialError("credential not found")

    def test_subclass_accepts_all_params(self):
        exc = ValidationError("msg", context=ErrorContext(), cause=ValueError("cause"))
        assert exc.message == "msg"
        assert exc.cause is not None


class TestExitCodeFor:
    def test_permission_denied_code(self):
        exc = PermissionDeniedError("denied")
        assert exit_code_for(exc) == 2

    def test_tool_not_found_code(self):
        exc = ToolNotFoundError("not found")
        assert exit_code_for(exc) == 3

    def test_llm_provider_error_code(self):
        exc = LLMProviderError("error")
        assert exit_code_for(exc) == 4

    def test_budget_exceeded_code(self):
        exc = BudgetExceededError("budget")
        assert exit_code_for(exc) == 1

    def test_validation_error_code(self):
        exc = ValidationError("bad")
        assert exit_code_for(exc) == 1

    def test_config_error_code(self):
        exc = ConfigError("config")
        assert exit_code_for(exc) == 1

    def test_tool_execution_error_code(self):
        exc = ToolExecutionError("exec")
        assert exit_code_for(exc) == 1

    def test_credential_error_code(self):
        exc = CredentialError("cred")
        assert exit_code_for(exc) == 1

    def test_base_siyarix_exception_code(self):
        exc = SiyarixException("generic")
        assert exit_code_for(exc) == 1

    def test_mro_fallback_unregistered_subclass(self):
        class CustomError(SiyarixException):
            pass

        exc = CustomError("custom")
        code = exit_code_for(exc)
        assert code == 1

    def test_mro_fallback_subclass_of_registered(self):
        class MyPermissionError(PermissionDeniedError):
            pass

        exc = MyPermissionError("denied")
        assert exit_code_for(exc) == 2

    def test_mro_fallback_subclass_of_tool_not_found(self):
        class MyToolError(ToolNotFoundError):
            pass

        exc = MyToolError("missing")
        assert exit_code_for(exc) == 3

    def test_mro_fallback_subclass_of_llm_error(self):
        class MyLLMError(LLMProviderError):
            pass

        exc = MyLLMError("timeout")
        assert exit_code_for(exc) == 4

    def test_unknown_type_default(self):
        class UnrelatedError(Exception):
            pass

        exc = UnrelatedError("unknown")
        code = exit_code_for(exc)
        assert code == 1


class TestPublicAPI:
    def test_all_exports(self):
        from siyarix import exceptions
        expected = [
            "SiyarixException",
            "ValidationError",
            "ErrorSeverity",
            "ErrorContext",
            "PermissionDeniedError",
            "BudgetExceededError",
            "ToolNotFoundError",
            "ToolExecutionError",
            "LLMProviderError",
            "ConfigError",
            "CredentialError",
            "exit_code_for",
        ]
        for name in expected:
            assert hasattr(exceptions, name)


import pytest
