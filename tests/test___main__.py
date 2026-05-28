# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.__main__ — CLI entry point."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch


def test_app_is_imported_from_main() -> None:
    from siyarix.__main__ import app

    assert callable(app)


def test_module_attributes() -> None:
    import siyarix.__main__

    assert hasattr(siyarix.__main__, "app")
    assert callable(siyarix.__main__.app)


@patch("siyarix.__main__.sys")
@patch("siyarix.__main__.app", return_value=0)
def test_main_block_calls_app(mock_app: MagicMock, mock_sys: MagicMock) -> None:
    import siyarix.__main__

    siyarix.__main__.sys.exit(siyarix.__main__.app())

    mock_app.assert_called_once_with()


@patch("siyarix.__main__.sys")
@patch("siyarix.__main__.app", return_value=1)
def test_main_block_passes_exit_code(mock_app: MagicMock, mock_sys: MagicMock) -> None:
    import siyarix.__main__

    siyarix.__main__.sys.exit(siyarix.__main__.app())

    mock_sys.exit.assert_called_once_with(1)


def test_main_block_via_subprocess() -> None:
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items()}
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("TERM", "xterm")
    result = subprocess.run(
        [sys.executable, "-m", "siyarix", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0
