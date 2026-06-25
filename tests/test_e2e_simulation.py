from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from siyarix.core import AgentCore, AgentMode, AgentGoal
from siyarix.planner import ExecutionPlan, PlanStep, StepStatus, PlanStatus
from siyarix.knowledge_graph import NodeType


@pytest.mark.asyncio
async def test_e2e_simulation_network_scan_and_enum():
    """
    E2E Simulation: Offline
    Goal: "Scan 192.168.1.1, if port 80 open, enumerate directories."
    """
    agent = AgentCore(mode=AgentMode.HYBRID)
    goal = AgentGoal(
        description="Scan 192.168.1.1, if port 80 open, enumerate directories.",
        target="192.168.1.1",
    )

    # Mock the LLM Planner to return a realistic plan
    plan = ExecutionPlan(goal=goal.description)
    step1 = PlanStep(id="s1", command="scan 192.168.1.1", tool="nmap")
    step2 = PlanStep(id="s2", command="enumerate 192.168.1.1", tool="gobuster")
    plan.steps = [step1, step2]

    # Mock Execution
    async def mock_execute_step(step, context):
        if step.tool == "nmap":
            step.status = StepStatus.COMPLETED
            step.result = {
                "stdout": "80/tcp open http",
                "findings": [{"port": 80, "service": "http"}],
            }
            # Add to KG
            agent._knowledge_graph.add_node(NodeType.PORT, "port_80", properties={"port": 80})
        elif step.tool == "gobuster":
            step.status = StepStatus.COMPLETED
            step.result = {"stdout": "/admin (Status: 200)", "findings": [{"path": "/admin"}]}
            agent._knowledge_graph.add_node(
                NodeType.URL, "path_admin", properties={"path": "/admin"}
            )
        return step

    with patch.object(agent._planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = plan

        async def mock_execute_plan(plan, *args, **kwargs):
            for step in plan.steps:
                await mock_execute_step(step, {})
            plan.status = PlanStatus.COMPLETED
            return plan

        with patch.object(
            agent._executor_autonomous, "execute_plan", side_effect=mock_execute_plan
        ):
            with patch.object(
                agent._validator, "validate_plan", new_callable=AsyncMock
            ) as mock_val:
                mock_val.return_value = (True, [])

                # Execute
                result = await agent.execute_goal(goal)

                # Assertions
                assert result.success is True
                assert len(result.plan.steps) == 2
                assert result.plan.steps[0].status == StepStatus.COMPLETED
                assert result.plan.steps[1].status == StepStatus.COMPLETED

                # Check Knowledge Graph
                assert any(n.label == "port_80" for n in agent._knowledge_graph._nodes.values())
                assert any(n.label == "path_admin" for n in agent._knowledge_graph._nodes.values())


@pytest.mark.asyncio
async def test_e2e_simulation_failure_and_recovery():
    """
    E2E Simulation: Offline
    Goal: "Exploit target" where a step fails and requires recovery.
    """
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    goal = AgentGoal(description="Exploit target", target="10.0.0.2")

    plan = ExecutionPlan(goal=goal.description)
    step1 = PlanStep(id="s1", command="exploit", tool="metasploit")
    plan.steps = [step1]

    execution_attempts = {"count": 0}

    async def mock_execute_plan(p, *args, **kwargs):
        execution_attempts["count"] += 1
        if execution_attempts["count"] == 1:
            p.steps[0].status = StepStatus.FAILED
            p.steps[0].result = {"error": "Connection refused"}
        else:
            p.steps[0].status = StepStatus.COMPLETED
            p.steps[0].result = {"stdout": "Exploit successful!"}
        p.status = (
            PlanStatus.COMPLETED if p.steps[0].status != StepStatus.FAILED else PlanStatus.FAILED
        )
        return p

    with patch.object(agent._planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = plan

        with patch.object(
            agent._executor_autonomous, "execute_plan", side_effect=mock_execute_plan
        ):
            with patch.object(
                agent._validator, "validate_plan", new_callable=AsyncMock
            ) as mock_val:
                mock_val.return_value = (True, [])

                with patch.object(
                    agent._validator, "plan_recovery", new_callable=AsyncMock
                ) as mock_rec:
                    from siyarix.validators import RecoveryAction, RecoveryPlan

                    # Provide recovery plan
                    mock_rec.return_value = RecoveryPlan(
                        original_step=step1,
                        action=RecoveryAction.RETRY,
                        modified_step=PlanStep(
                            id="s1", command="exploit", tool="metasploit", args={"retry": True}
                        ),
                        message="Retrying exploit",
                    )

                    result = await agent.execute_goal(goal)

                    assert execution_attempts["count"] == 2
                    assert result.success is True


@pytest.mark.asyncio
async def test_e2e_simulation_swarm_routing():
    """
    E2E Simulation: Offline
    Goal: "Check database for vulnerabilities" triggers a specialized subagent.
    """
    agent = AgentCore(mode=AgentMode.AUTONOMOUS)
    goal = AgentGoal(description="Check database for vulnerabilities", target="10.0.0.3")

    plan = ExecutionPlan(goal=goal.description)
    # The step uses the swarm subagent
    step1 = PlanStep(
        id="s1",
        command="Check database",
        tool="_subagent",
        args={"role": "database_specialist", "goal": "Audit DB on 10.0.0.3"},
    )
    plan.steps = [step1]

    with patch.object(agent._planner_autonomous, "plan", new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = plan

        async def mock_execute_plan(p, *args, **kwargs):
            # Simulate the executor calling execute_subagent
            role = p.steps[0].args.get("role")
            goal_desc = p.steps[0].args.get("goal")
            res = await agent.execute_subagent(role, goal_desc)
            if res:
                p.steps[0].status = StepStatus.COMPLETED
            else:
                p.steps[0].status = StepStatus.FAILED
            p.status = PlanStatus.COMPLETED
            return p

        with patch.object(
            agent._executor_autonomous, "execute_plan", side_effect=mock_execute_plan
        ):
            with patch.object(
                agent._validator, "validate_plan", new_callable=AsyncMock
            ) as mock_val:
                mock_val.return_value = (True, [])

                with patch.object(
                    agent, "execute_subagent", new_callable=AsyncMock
                ) as mock_subagent:
                    mock_subagent.return_value = MagicMock(findings=[1, 2, 3])

                    result = await agent.execute_goal(goal)

                    assert result.success is True
                    assert result.plan.steps[0].status == StepStatus.COMPLETED
                    mock_subagent.assert_called_once_with(
                        "database_specialist", "Audit DB on 10.0.0.3"
                    )
