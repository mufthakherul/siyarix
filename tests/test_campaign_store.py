# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for persistent multi-target campaign store and /campaign wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.campaign import (
    CampaignStore,
    load_targets_file,
    sanitize_campaign_name,
)


def test_sanitize_campaign_name() -> None:
    assert sanitize_campaign_name(" Eng One! ") == "Eng-One"
    assert sanitize_campaign_name("///") == "campaign"


def test_load_targets_file(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("# lab\n10.0.0.1\n\n10.0.0.2\n", encoding="utf-8")
    assert load_targets_file(path) == ["10.0.0.1", "10.0.0.2"]


def test_campaign_store_roundtrip(tmp_path: Path) -> None:
    store = CampaignStore(base_dir=tmp_path / "campaigns")
    camp = store.create("lab-eng", ["10.0.0.1", "10.0.0.1", "host.lab"], notes="RoE")
    assert camp.name == "lab-eng"
    assert camp.targets == ["10.0.0.1", "host.lab"]
    assert camp.notes == "RoE"
    assert store.targets_file(camp.name).is_file()
    assert store.targets_file(camp.name).read_text(encoding="utf-8").splitlines() == [
        "10.0.0.1",
        "host.lab",
    ]
    listed = store.list_campaigns()
    assert len(listed) == 1
    assert listed[0].name == "lab-eng"
    marked = store.mark_run("lab-eng")
    assert marked is not None
    assert marked.run_count == 1
    assert marked.status == "running"
    assert marked.last_run_at
    with pytest.raises(ValueError, match="already exists"):
        store.create("lab-eng", ["1.2.3.4"])
    assert store.delete("lab-eng") is True
    assert store.get("lab-eng") is None
    assert store.delete("missing") is False


@pytest.mark.asyncio
async def test_cmd_campaign_create_list_status_run_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from siyarix.chat import SiyarixChat

    camp_dir = tmp_path / "campaigns"
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("10.1.2.3\n10.1.2.4\n", encoding="utf-8")
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path))

    chat = SiyarixChat()
    with patch("siyarix.chat.handlers.console.print") as mock_print:
        with patch("siyarix.campaign.get_config_dir", return_value=tmp_path):
            await chat._cmd_campaign(f"create eng1 --targets {hosts}")
            await chat._cmd_campaign("list")
            await chat._cmd_campaign("status eng1")
            await chat._cmd_campaign("run eng1")
            await chat._cmd_campaign("delete eng1")

    printed = " ".join(str(c.args[0]) for c in mock_print.call_args_list if c.args)
    assert "Campaign created: eng1" in printed
    assert "scan-quick" in printed
    assert "Deleted campaign: eng1" in printed
    assert not (camp_dir / "eng1.json").exists()
