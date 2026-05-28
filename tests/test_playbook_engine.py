# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for PlaybookEngine."""

from __future__ import annotations

from pathlib import Path

import pytest

from siyarix.playbook_engine import (Playbook, PlaybookEngine, PlaybookStep,
                                     PlaybookStepType)

pytestmark = pytest.mark.playbook


class TestPlaybookEngine:
    @pytest.fixture
    def engine(self, tmp_path: Path):
        return PlaybookEngine(playbooks_dir=tmp_path)

    def test_save_and_load(self, engine):
        playbook = Playbook(name="test-pb", description="Test playbook")
        playbook.steps = [PlaybookStep(name="step1", command="nmap -sV {target}")]
        engine.save(playbook)
        loaded = engine.load("test-pb")
        assert loaded is not None
        assert loaded.name == "test-pb"
        assert len(loaded.steps) == 1

    def test_list_playbooks(self, engine):
        pb1 = Playbook(name="pb1", description="First")
        pb2 = Playbook(name="pb2", description="Second")
        engine.save(pb1)
        engine.save(pb2)
        playbooks = engine.list_playbooks()
        assert len(playbooks) == 2

    def test_delete_playbook(self, engine):
        playbook = Playbook(name="delete-me")
        engine.save(playbook)
        assert engine.delete("delete-me") is True
        assert engine.load("delete-me") is None

    def test_delete_nonexistent(self, engine):
        assert engine.delete("nonexistent") is False

    def test_load_nonexistent(self, engine):
        assert engine.load("nonexistent") is None

    def test_resolve_variables(self):
        playbook = Playbook(
            name="test", variables={"target": "example.com", "port": "80"}
        )
        resolved = playbook.resolve_variables("nmap -p {port} {target}")
        assert resolved == "nmap -p 80 example.com"

    def test_resolve_variables_extra(self):
        playbook = Playbook(name="test", variables={"target": "example.com"})
        resolved = playbook.resolve_variables(
            "scan {target}", extra_vars={"target": "override.com"}
        )
        assert resolved == "scan override.com"

    def test_create_bugbounty_recon(self, engine):
        playbook = engine.create_bugbounty_recon()
        assert playbook.name == "bugbounty-recon"
        assert len(playbook.steps) >= 5

    def test_create_incident_response(self, engine):
        playbook = engine.create_incident_response()
        assert playbook.name == "incident-response"
        assert len(playbook.steps) >= 4

    def test_install_builtins(self, engine):
        installed = engine.install_builtins()
        assert "bugbounty-recon" in installed
        assert "incident-response" in installed

    def test_playbook_step_defaults(self):
        step = PlaybookStep(name="test")
        assert step.step_type == PlaybookStepType.COMMAND
        assert step.on_error == "abort"
        assert step.max_retries == 1

    def test_playbook_dataclass(self):
        pb = Playbook(
            name="test", version="2.0", author="Test Author", tags=["web", "recon"]
        )
        assert pb.name == "test"
        assert pb.version == "2.0"
        assert "web" in pb.tags
