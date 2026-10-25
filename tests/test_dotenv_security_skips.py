# SPDX-License-Identifier: AGPL-3.0-or-later
"""cwd .env must not flip security posture or inject interpreter hooks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from siyarix.cli import _load_dotenv


def test_load_dotenv_skips_security_posture_and_inject_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SIYARIX_SAFE_MODE=0",
                "SIYARIX_PREAUTHORIZED=1",
                "SIYARIX_COMMAND_REVIEW=false",
                "SIYARIX_ALLOWED_SCOPE=0.0.0.0/0",
                "PERL5OPT=-d:Foo",
                "RUBYOPT=-rfoo",
                "JAVA_TOOL_OPTIONS=-javaagent:x",
                "HTTPS_PROXY=http://evil",
                "PROMPT_COMMAND=evil",
                "SIYARIX_HARMLESS=ok",
            ]
        ),
        encoding="utf-8",
    )
    for key in (
        "SIYARIX_SAFE_MODE",
        "SIYARIX_PREAUTHORIZED",
        "SIYARIX_COMMAND_REVIEW",
        "SIYARIX_ALLOWED_SCOPE",
        "PERL5OPT",
        "RUBYOPT",
        "JAVA_TOOL_OPTIONS",
        "HTTPS_PROXY",
        "PROMPT_COMMAND",
        "SIYARIX_HARMLESS",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.chdir(tmp_path)
    _load_dotenv(env_file)

    assert "SIYARIX_SAFE_MODE" not in os.environ
    assert "SIYARIX_PREAUTHORIZED" not in os.environ
    assert "SIYARIX_COMMAND_REVIEW" not in os.environ
    assert "SIYARIX_ALLOWED_SCOPE" not in os.environ
    assert "PERL5OPT" not in os.environ
    assert "RUBYOPT" not in os.environ
    assert "JAVA_TOOL_OPTIONS" not in os.environ
    assert "HTTPS_PROXY" not in os.environ
    assert "PROMPT_COMMAND" not in os.environ
    assert os.environ.get("SIYARIX_HARMLESS") == "ok"
