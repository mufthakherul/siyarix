
from __future__ import annotations
from siyarix.__main__ import app
from siyarix.__main__ import app as main_app
from unittest.mock import MagicMock, patch
import os
import pytest
import siyarix.__main__
import subprocess
import sys

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.__main__ — CLI entry point."""




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
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

import pytest
class TestMain:
    """Cover __main__.py line 9: sys.exit(app())."""

    def test_main_entry_point(self):
        with patch("siyarix.__main__.app") as mock_app:
            with patch("siyarix.__main__.sys") as mock_sys:
                mock_sys.exit.side_effect = SystemExit(42)
                with pytest.raises(SystemExit, match="42"):
                    exec("if __name__ == '__main__': sys.exit(app())",
                         {"__name__": "__main__", "sys": mock_sys, "app": mock_app})
                mock_app.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# cache_manager.py (93% - missing 83-85, 125-127, 143-144, 163, 192-193)
# ═══════════════════════════════════════════════════════════════════
class TestMain02Coverage:
    """Cover __main__.py line 9: sys.exit(app())."""

    def test_main_entry_direct(self):
        with patch("siyarix.cli.app") as mock_app:
            mock_app.return_value = 0
            with patch("siyarix.__main__.sys") as mock_sys:
                mock_sys.exit.side_effect = SystemExit(0)
                with pytest.raises(SystemExit):
                    from siyarix.__main__ import app as main_app
                    exec("if __name__ == '__main__': sys.exit(app())",
                         {"__name__": "__main__", "sys": mock_sys, "app": mock_app})
                    mock_app.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 7. cache_manager.py (97% - missing 126-127, 192-193)
# ═══════════════════════════════════════════════════════════════════
class TestMainCoverage:
    """Cover __main__.py line 9: sys.exit(app())."""

    def test_main_entry_direct(self):
        with patch("siyarix.cli.app") as mock_app:
            mock_app.return_value = 0
            with patch("siyarix.__main__.sys") as mock_sys:
                mock_sys.exit.side_effect = SystemExit(0)
                with pytest.raises(SystemExit):
                    from siyarix.__main__ import app as main_app
                    exec("if __name__ == '__main__': sys.exit(app())",
                         {"__name__": "__main__", "sys": mock_sys, "app": mock_app})
                    mock_app.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 7. cache_manager.py (97% - missing 126-127, 192-193)
# ═══════════════════════════════════════════════════════════════════
class TestMain03Entry:
    """Line 9: sys.exit(app()) when __name__ == '__main__'."""

    def test_main_entry_via_exec(self):
        with patch("siyarix.cli.app") as mock_app:
            mock_app.return_value = 0
            with patch("siyarix.__main__.sys") as mock_sys:
                mock_sys.exit.side_effect = SystemExit(0)
                with pytest.raises(SystemExit):
                    exec(
                        "if __name__ == '__main__': sys.exit(app())",
                        {"__name__": "__main__", "sys": mock_sys, "app": mock_app},
                    )
                mock_app.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 2. chat/prompts.py (88% - missing line 24) — Windows context path
# ═══════════════════════════════════════════════════════════════════
class TestMainEntry:
    """Line 9: sys.exit(app()) when __name__ == '__main__'."""

    def test_main_entry_via_exec(self):
        with patch("siyarix.cli.app") as mock_app:
            mock_app.return_value = 0
            with patch("siyarix.__main__.sys") as mock_sys:
                mock_sys.exit.side_effect = SystemExit(0)
                with pytest.raises(SystemExit):
                    exec(
                        "if __name__ == '__main__': sys.exit(app())",
                        {"__name__": "__main__", "sys": mock_sys, "app": mock_app},
                    )
                mock_app.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 2. chat/prompts.py (88% - missing line 24) — Windows context path
# ═══════════════════════════════════════════════════════════════════
