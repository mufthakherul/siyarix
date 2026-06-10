# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import UTC, datetime

import pytest

from siyarix.metrics import (
    ExecutionMetrics,
    Metric,
    MetricType,
    MetricsCollector,
    PlannerMetrics,
    ToolMetrics,
    get_metrics,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    MetricsCollector._instance = None
    yield


@pytest.fixture
def collector():
    return MetricsCollector()


class TestMetric:
    def test_to_prometheus_with_labels(self):
        m = Metric(
            "test_metric",
            MetricType.COUNTER,
            42,
            labels={"env": "prod", "host": "h1"},
            timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        )
        result = m.to_prometheus()
        assert 'test_metric{env="prod",host="h1"} 42' in result

    def test_to_prometheus_without_labels(self):
        m = Metric(
            "simple", MetricType.GAUGE, 3.14, timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        )
        result = m.to_prometheus()
        assert "simple 3.14" in result

    def test_metric_defaults(self):
        m = Metric(name="m", type=MetricType.COUNTER, value=1)
        assert m.labels == {}
        assert isinstance(m.timestamp, datetime)


class TestExecutionMetrics:
    def test_to_metrics(self):
        em = ExecutionMetrics(
            total_scans=10,
            successful_scans=8,
            failed_scans=2,
            total_findings=25,
            total_duration_seconds=100.0,
            average_duration_seconds=10.0,
        )
        metrics = em.to_metrics()
        assert len(metrics) == 6
        names = [m.name for m in metrics]
        assert "siyarix_scans_total" in names
        assert "siyarix_scans_successful" in names

    def test_defaults(self):
        em = ExecutionMetrics()
        assert em.total_scans == 0


class TestToolMetrics:
    def test_to_metrics(self):
        tm = ToolMetrics(
            tool_name="nmap",
            executions=5,
            successful=3,
            failed=2,
            total_duration_seconds=50.0,
            findings_count=100,
        )
        metrics = tm.to_metrics()
        assert len(metrics) == 4
        for m in metrics:
            assert m.labels.get("tool") == "nmap"

    def test_defaults(self):
        tm = ToolMetrics(tool_name="test")
        assert tm.executions == 0


class TestPlannerMetrics:
    def test_to_metrics(self):
        pm = PlannerMetrics(
            plans_generated=5, plans_successful=3, plans_failed=2, model_calls=10, model_errors=1
        )
        metrics = pm.to_metrics()
        assert len(metrics) == 5
        names = [m.name for m in metrics]
        assert "siyarix_plans_generated" in names


class TestMetricsCollector:
    def test_singleton(self):
        m1 = MetricsCollector.instance()
        m2 = MetricsCollector.instance()
        assert m1 is m2

    def test_init(self, collector):
        assert collector.execution.total_scans == 0
        assert collector.planner.plans_generated == 0
        assert collector.tools == {}

    def test_uptime_seconds(self, collector):
        up1 = collector.uptime_seconds()
        up2 = collector.uptime_seconds()
        assert up2 >= up1

    def test_record_scan_success(self, collector):
        collector.record_scan(duration=5.0, successful=True, findings_count=10)
        assert collector.execution.total_scans == 1
        assert collector.execution.successful_scans == 1
        assert collector.execution.failed_scans == 0
        assert collector.execution.total_findings == 10
        assert collector.execution.average_duration_seconds == 5.0

    def test_record_scan_failure(self, collector):
        collector.record_scan(duration=2.0, successful=False)
        assert collector.execution.total_scans == 1
        assert collector.execution.successful_scans == 0
        assert collector.execution.failed_scans == 1

    def test_record_scan_multiple(self, collector):
        collector.record_scan(duration=10.0, successful=True)
        collector.record_scan(duration=20.0, successful=True)
        assert collector.execution.average_duration_seconds == 15.0

    def test_record_tool_execution_new_tool(self, collector):
        collector.record_tool_execution(
            tool_name="nmap", duration=3.0, successful=True, findings_count=5
        )
        assert "nmap" in collector.tools
        assert collector.tools["nmap"].executions == 1
        assert collector.tools["nmap"].successful == 1

    def test_record_tool_execution_existing_tool(self, collector):
        collector.record_tool_execution(tool_name="nmap", duration=3.0, successful=True)
        collector.record_tool_execution(tool_name="nmap", duration=2.0, successful=False)
        assert collector.tools["nmap"].executions == 2
        assert collector.tools["nmap"].successful == 1
        assert collector.tools["nmap"].failed == 1
        assert collector.tools["nmap"].total_duration_seconds == 5.0

    def test_record_plan_generation_success(self, collector):
        collector.record_plan_generation(successful=True, used_model=True)
        assert collector.planner.plans_generated == 1
        assert collector.planner.plans_successful == 1
        assert collector.planner.model_calls == 1

    def test_record_plan_generation_failure(self, collector):
        collector.record_plan_generation(successful=False, used_model=False)
        assert collector.planner.plans_generated == 1
        assert collector.planner.plans_failed == 1
        assert collector.planner.model_calls == 0

    def test_record_model_error(self, collector):
        collector.record_model_error()
        assert collector.planner.model_errors == 1

    def test_to_prometheus(self, collector):
        collector.record_scan(duration=1.0, successful=True, findings_count=3)
        collector.record_tool_execution(tool_name="nmap", duration=2.0, successful=True)
        collector.record_plan_generation(successful=True)
        prom = collector.to_prometheus()
        assert "siyarix_uptime" in prom
        assert "siyarix_scans_total" in prom
        assert "siyarix_tool_executions" in prom
        assert "siyarix_plans_generated" in prom

    def test_to_dict(self, collector):
        collector.record_scan(duration=1.0, successful=True)
        collector.record_tool_execution(
            tool_name="test_tool", duration=0.5, successful=True, findings_count=7
        )
        collector.record_plan_generation(successful=True)
        d = collector.to_dict()
        assert d["execution"]["total_scans"] == 1
        assert d["tools"]["test_tool"]["findings_count"] == 7
        assert d["planner"]["plans_generated"] == 1
        assert d["uptime_seconds"] >= 0

    def test_get_metrics_function(self):
        m = get_metrics()
        assert isinstance(m, MetricsCollector)

    def test_record_tool_with_findings(self, collector):
        collector.record_tool_execution(
            tool_name="nuclei", duration=1.0, successful=True, findings_count=15
        )
        assert collector.tools["nuclei"].findings_count == 15

    def test_to_prometheus_multiple_tools(self, collector):
        collector.record_tool_execution(tool_name="a", duration=1.0, successful=True)
        collector.record_tool_execution(tool_name="b", duration=2.0, successful=False)
        prom = collector.to_prometheus()
        assert 'siyarix_tool_executions{tool="a"}' in prom
        assert 'siyarix_tool_executions{tool="b"}' in prom
