# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.logging_config — centralized logging configuration."""

from __future__ import annotations

import json
import logging
import sys

import pytest

from siyarix.logging_config import _JSONFormatter, configure_logging


class TestJSONFormatter:
    def test_format_basic(self) -> None:
        formatter = _JSONFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["name"] == "test_logger"
        assert data["msg"] == "hello world"
        assert "ts" in data

    def test_format_with_exc_info(self) -> None:
        formatter = _JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            record = logging.LogRecord(
                name="test_logger",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "ERROR"
        assert data["msg"] == "error occurred"
        assert "exc" in data
        assert "ValueError" in data["exc"]

    def test_format_debug_level(self) -> None:
        formatter = _JSONFormatter()
        record = logging.LogRecord(
            name="debug_logger",
            level=logging.DEBUG,
            pathname="test.py",
            lineno=1,
            msg="debug info",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "DEBUG"


def _reset_root_logger() -> list[logging.Handler]:
    root = logging.getLogger()
    old_handlers = list(root.handlers)
    _old_level = root.level
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(logging.WARNING)
    return old_handlers


class TestConfigureLogging:
    def test_configure_with_default_level(self) -> None:
        _reset_root_logger()
        try:
            configure_logging()
            root = logging.getLogger()
            assert root.level == logging.INFO
        finally:
            root = logging.getLogger()

    def test_configure_with_specific_level(self) -> None:
        _reset_root_logger()
        try:
            configure_logging(level="DEBUG")
            root = logging.getLogger()
            assert root.level == logging.DEBUG
        finally:
            root = logging.getLogger()

    def test_configure_with_invalid_level_falls_back_to_info(self) -> None:
        _reset_root_logger()
        try:
            configure_logging(level="NOT_A_REAL_LEVEL")
            root = logging.getLogger()
            assert root.level == logging.INFO
        finally:
            root = logging.getLogger()

    def test_configure_with_console_disabled(self) -> None:
        _reset_root_logger()
        try:
            configure_logging(enable_console=False)
            root = logging.getLogger()
            assert root.level == logging.INFO
            assert len(root.handlers) == 0
        finally:
            root = logging.getLogger()

    def test_configure_adds_stream_handler(self) -> None:
        _reset_root_logger()
        try:
            configure_logging()
            root = logging.getLogger()
            assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)
        finally:
            root = logging.getLogger()

    def test_configure_skips_duplicate_handlers(self) -> None:
        _reset_root_logger()
        try:
            configure_logging()
            configure_logging()  # second call should not add a duplicate
            root = logging.getLogger()
            stream_handlers = [
                h for h in root.handlers if isinstance(h, logging.StreamHandler)
            ]
            assert len(stream_handlers) == 1
        finally:
            root = logging.getLogger()

    def test_configure_formatter_is_json(self) -> None:
        _reset_root_logger()
        try:
            configure_logging()
            root = logging.getLogger()
            for h in root.handlers:
                if isinstance(h, logging.StreamHandler) and h.formatter:
                    assert isinstance(h.formatter, _JSONFormatter)
                    return
            pytest.fail("No StreamHandler with formatter found")
        finally:
            root = logging.getLogger()
