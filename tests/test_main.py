from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests that siyarix.main re-exports app from siyarix.cli."""


from siyarix.cli import app as cli_app
from siyarix.main import __all__, app


def test_app_is_re_exported() -> None:
    assert app is cli_app


def test_all_contains_app() -> None:
    assert "app" in __all__
    assert len(__all__) == 1



"""Final coverage tests for siyarix.main — covers the single re-export."""




def test_app_is_re_exported() -> None:
    assert app is cli_app


def test_all_contains_app() -> None:
    assert "app" in __all__
    assert len(__all__) == 1