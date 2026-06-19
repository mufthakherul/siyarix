"""Tests for src/siyarix/providers/ollama_utils.py — 100% coverage."""

from __future__ import annotations

import os as _real_os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import httpx

import pytest


# CREATE_NO_WINDOW only exists on Windows
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


class TestEnsureOllamaRunning:
    def test_should_start_false_not_ollama_provider(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "openai",
            "_start_ollama_on_launch": False,
        }.get(key, default)

        with patch("siyarix.config.SettingsStore", return_value=mock_settings):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_settings.get.assert_any_call("model_provider")

    def test_should_start_false_start_on_launch_false(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": False,
        }.get(key, default)

        with patch("siyarix.config.SettingsStore", return_value=mock_settings):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

    def test_ollama_already_running(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", return_value=mock_response) as mock_get,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_get.assert_called_once_with("http://localhost:11434/api/tags", timeout=3)

    def test_ollama_running_status_500(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        mock_response = MagicMock()
        mock_response.status_code = 500

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", return_value=mock_response),
            patch("siyarix.providers.ollama_utils.shutil.which", return_value=None) as mock_which,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_which.assert_called_once_with("ollama")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_ollama_not_reachable_starts_it_windows(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", side_effect=Exception("Connection refused")),
            patch("siyarix.providers.ollama_utils.shutil.which", return_value="/usr/bin/ollama") as mock_which,
            patch("siyarix.providers.ollama_utils.os.name", "nt"),
            patch("siyarix.providers.ollama_utils.subprocess.CREATE_NO_WINDOW", _CREATE_NO_WINDOW),
            patch("siyarix.providers.ollama_utils.subprocess.Popen") as mock_popen,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_which.assert_called_once_with("ollama")
        mock_popen.assert_called_once_with(
            ["ollama", "serve"],
            creationflags=_CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_ollama_not_reachable_starts_it_non_windows(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", side_effect=Exception("Connection refused")),
            patch("siyarix.providers.ollama_utils.shutil.which", return_value="/usr/local/bin/ollama") as mock_which,
            patch("siyarix.providers.ollama_utils.os.name", "posix"),
            patch("siyarix.providers.ollama_utils.subprocess.Popen") as mock_popen,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_popen.assert_called_once_with(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_ollama_not_reachable_no_binary(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", side_effect=Exception("Connection refused")),
            patch("siyarix.providers.ollama_utils.shutil.which", return_value=None) as mock_which,
            patch("siyarix.providers.ollama_utils.subprocess.Popen") as mock_popen,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_which.assert_called_once_with("ollama")
        mock_popen.assert_not_called()

    def test_outer_exception_handling(self) -> None:
        with patch(
            "siyarix.config.SettingsStore",
            side_effect=Exception("Unexpected failure"),
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

    def test_default_ollama_url_when_not_configured(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": True,
        }.get(key, default)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", return_value=mock_response) as mock_get,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_get.assert_called_once_with("http://localhost:11434/api/tags", timeout=3)

    def test_provider_is_ollama_should_start_true(self) -> None:
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: {
            "model_provider": "ollama",
            "_start_ollama_on_launch": False,
            "ollama_url": "http://localhost:11434",
        }.get(key, default)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("siyarix.config.SettingsStore", return_value=mock_settings),
            patch.object(httpx, "get", return_value=mock_response) as mock_get,
        ):
            from siyarix.providers.ollama_utils import ensure_ollama_running
            ensure_ollama_running()

        mock_get.assert_called_once()
