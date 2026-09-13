# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for /memory and enhanced /skills commands in Siyarix chat."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from siyarix.chat import SiyarixChat
from siyarix.learning_system import get_learning_system, LearnedSkill, LearnedStep


@pytest.fixture
def chat():
    return SiyarixChat()


@pytest.fixture
def mock_console():
    from siyarix.chat.console import console

    with patch.object(console, "print") as mock_print:
        yield MagicMock(print=mock_print)


@pytest.mark.asyncio
async def test_cmd_memory_stats(chat, mock_console):
    await chat._cmd_memory("stats")
    mock_console.print.assert_called()


@pytest.mark.asyncio
async def test_cmd_memory_list_empty(chat, mock_console):
    with patch.object(chat._session, "list_memories", return_value=[]):
        await chat._cmd_memory("list")
        mock_console.print.assert_called_with("[yellow]No memory entries found.[/yellow]")


@pytest.mark.asyncio
async def test_cmd_memory_list_populated(chat, mock_console):
    chat._session.remember_target("target.local", {"ports": [80, 443]})
    await chat._cmd_memory("list 10")
    mock_console.print.assert_called()


@pytest.mark.asyncio
async def test_cmd_memory_search(chat, mock_console):
    chat._session.remember_target("example.com", {"ports": [8080], "technologies": ["nginx"]})
    await chat._cmd_memory("search nginx")
    mock_console.print.assert_called()


@pytest.mark.asyncio
async def test_cmd_memory_target(chat, mock_console):
    chat._session.remember_target(
        "192.168.1.100",
        {"ports": [22, 80], "findings": [{"title": "Open SSH", "severity": "info"}]},
    )
    await chat._cmd_memory("target 192.168.1.100")
    mock_console.print.assert_called()


@pytest.mark.asyncio
async def test_cmd_memory_target_not_found(chat, mock_console):
    await chat._cmd_memory("target unknown.host")
    mock_console.print.assert_called_with(
        "[yellow]No stored intelligence found for target 'unknown.host'.[/yellow]"
    )


@pytest.mark.asyncio
async def test_cmd_skills_search(chat, mock_console):
    cls = get_learning_system()
    skill = LearnedSkill(
        skill_id="test_search_skill_01",
        intent_pattern="port scan {target} fast",
        steps=[
            LearnedStep(tool="nmap", command_template="nmap -F {target}", description="Fast scan")
        ],
        confidence=0.9,
        usage_count=5,
        success_count=5,
        tokens=["port", "scan", "fast"],
        synonyms={},
        created_at=1000.0,
        last_used=1000.0,
        source="manual",
    )
    cls._skills[skill.skill_id] = skill
    await chat._cmd_skills("search nmap")
    mock_console.print.assert_called()
    # Cleanup
    cls.delete_skill(skill.skill_id)


@pytest.mark.asyncio
async def test_cmd_skills_import_and_run(chat, mock_console):
    cls = get_learning_system()
    export_data = {
        "skills": [
            {
                "skill_id": "test_import_01",
                "intent_pattern": "custom ping check {target}",
                "confidence": 0.85,
                "usage_count": 2,
                "success_count": 2,
                "tokens": ["custom", "ping", "check"],
                "steps": [
                    {
                        "tool": "ping",
                        "command_template": "ping -c 1 {target}",
                        "description": "Ping host",
                        "args": {},
                    }
                ],
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(json.dumps(export_data))
        temp_path = f.name

    try:
        await chat._cmd_skills(f"import {temp_path}")
        assert "test_import_01" in cls._skills

        # Test skills search finding the imported skill
        await chat._cmd_skills("search ping")
        mock_console.print.assert_called()

        # Test skills run with mock executor
        with (
            patch("siyarix.core.AgentCore.initialize", new_callable=AsyncMock),
            patch(
                "siyarix.executor_autonomous.AutonomousExecutor.execute_plan",
                new_callable=AsyncMock,
            ) as mock_exec,
        ):
            res_mock = MagicMock()
            res_mock.status.name = "COMPLETED"
            mock_exec.return_value = res_mock

            await chat._cmd_skills("run test_import_01 127.0.0.1")
            mock_exec.assert_called_once()
    finally:
        Path(temp_path).unlink(missing_ok=True)
        cls.delete_skill("test_import_01")


def test_enhanced_similarity_synonyms_and_weights():
    cls = get_learning_system()
    # 1. Test synonym mapping: dirbust -> directory
    tokens_a = ["dirbust", "target"]
    tokens_b = ["directory", "target"]
    sim = cls._compute_similarity(tokens_a, tokens_b)
    # Since dirbust maps to directory, both tokens match!
    assert sim >= 0.9

    # 2. Test domain weight boost: high-importance terms like nmap get weighted heavily
    tokens_scan1 = ["nmap", "port", "scan"]
    tokens_scan2 = ["nmap", "fast", "scan"]
    sim_domain = cls._compute_similarity(tokens_scan1, tokens_scan2)
    assert sim_domain > 0.5
