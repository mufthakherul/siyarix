# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.compat import ExecutionEngine, ExecutionMode
from siyarix.core import AgentCore, AgentMode


def test_engine_creation_with_default_config():
    engine = ExecutionEngine(mode=ExecutionMode.INTEGRATED)
    assert engine._mode == ExecutionMode.INTEGRATED


def test_engine_creation_with_registry_mode():
    engine = ExecutionEngine(mode=ExecutionMode.REGISTRY)
    assert engine._mode == ExecutionMode.REGISTRY


def test_agent_core_has_providers():
    agent = AgentCore(mode=AgentMode.HYBRID)
    assert agent.providers is not None


def test_agent_core_has_memory():
    agent = AgentCore(mode=AgentMode.REGISTRY)
    assert agent.memory is not None


def test_agent_core_has_registry():
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    assert agent.registry is not None
