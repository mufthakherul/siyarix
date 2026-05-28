# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime

import pytest

from siyarix.agent_lifecycle import AgentInstance, AgentLifecycle


@pytest.fixture
def lifecycle():
    return AgentLifecycle()


class TestAgentLifecycle:
    def test_init(self, lifecycle):
        assert lifecycle._agents == {}

    def test_spawn(self, lifecycle):
        agent = lifecycle.spawn(name="test-agent", task="scan network")
        assert agent.name == "test-agent"
        assert agent.task == "scan network"
        assert agent.status == "running"
        assert agent.id != ""
        assert len(agent.id) == 8
        assert agent.id in lifecycle._agents

    def test_spawn_without_task(self, lifecycle):
        agent = lifecycle.spawn(name="minimal")
        assert agent.name == "minimal"
        assert agent.task == ""

    def test_list_agents_empty(self, lifecycle):
        assert lifecycle.list_agents() == []

    def test_list_agents(self, lifecycle):
        lifecycle.spawn("agent1")
        lifecycle.spawn("agent2")
        agents = lifecycle.list_agents()
        assert len(agents) == 2

    def test_kill_existing(self, lifecycle):
        agent = lifecycle.spawn("test")
        assert lifecycle.kill(agent.id) is True
        assert lifecycle._agents[agent.id].status == "completed"

    def test_kill_nonexistent(self, lifecycle):
        assert lifecycle.kill("nonexistent") is False

    def test_get_existing(self, lifecycle):
        agent = lifecycle.spawn("test")
        retrieved = lifecycle.get(agent.id)
        assert retrieved is not None
        assert retrieved.name == "test"

    def test_get_nonexistent(self, lifecycle):
        assert lifecycle.get("nonexistent") is None

    def test_show_table_with_agents(self, lifecycle):
        lifecycle.spawn("agent_a", task="recon")
        lifecycle.spawn("agent_b", task="exploit")
        lifecycle.show_table()

    def test_show_table_no_agents(self, lifecycle):
        lifecycle.show_table()

    def test_agent_instance_dataclass(self):
        now = datetime.now()
        agent = AgentInstance(id="abc12345", name="my-agent", created_at=now, status="running", task="test task")
        assert agent.id == "abc12345"
        assert agent.name == "my-agent"
        assert agent.created_at == now
        assert agent.status == "running"
        assert agent.task == "test task"

    def test_agent_instance_defaults(self):
        agent = AgentInstance(id="id12345", name="defaults")
        assert agent.status == "idle"
        assert agent.task == ""

    def test_kill_updates_status_only(self, lifecycle):
        agent = lifecycle.spawn("test")
        lifecycle.kill(agent.id)
        assert lifecycle._agents[agent.id].status == "completed"
        assert lifecycle._agents[agent.id].name == "test"

    def test_spawn_unique_ids(self, lifecycle):
        a1 = lifecycle.spawn("a")
        a2 = lifecycle.spawn("b")
        assert a1.id != a2.id
