"""Metrics collection with Prometheus support."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum

__all__ = [
    "MetricsCollector",
    "ExecutionMetrics",
    "ToolMetrics",
    "PlannerMetrics",
    "get_metrics",
]


class MetricType(StrEnum):
    """Metric types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Metric:
    """Single metric measurement."""
    name: str
    type: MetricType
    value: float | int
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_prometheus(self) -> str:
        """Format as Prometheus line."""
        labels_str = ""
        if self.labels:
            labels_str = "{" + ",".join(f'{k}="{v}"' for k, v in self.labels.items()) + "}"
        
        timestamp_ms = int(self.timestamp.timestamp() * 1000)
        return f"{self.name}{labels_str} {self.value} {timestamp_ms}"


@dataclass
class ExecutionMetrics:
    """Execution-level metrics."""
    total_scans: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    total_findings: int = 0
    total_duration_seconds: float = 0.0
    average_duration_seconds: float = 0.0
    
    def to_metrics(self) -> list[Metric]:
        """Convert to Prometheus metrics."""
        return [
            Metric("siyarix_scans_total", MetricType.COUNTER, self.total_scans),
            Metric("siyarix_scans_successful", MetricType.GAUGE, self.successful_scans),
            Metric("siyarix_scans_failed", MetricType.GAUGE, self.failed_scans),
            Metric("siyarix_findings_total", MetricType.GAUGE, self.total_findings),
            Metric("siyarix_execution_duration_seconds", MetricType.GAUGE, self.total_duration_seconds),
            Metric("siyarix_execution_avg_duration_seconds", MetricType.GAUGE, self.average_duration_seconds),
        ]


@dataclass
class ToolMetrics:
    """Tool-specific metrics."""
    tool_name: str
    executions: int = 0
    successful: int = 0
    failed: int = 0
    total_duration_seconds: float = 0.0
    findings_count: int = 0
    
    def to_metrics(self) -> list[Metric]:
        """Convert to Prometheus metrics."""
        return [
            Metric(
                "siyarix_tool_executions",
                MetricType.GAUGE,
                self.executions,
                {"tool": self.tool_name},
            ),
            Metric(
                "siyarix_tool_successful",
                MetricType.GAUGE,
                self.successful,
                {"tool": self.tool_name},
            ),
            Metric(
                "siyarix_tool_failed",
                MetricType.GAUGE,
                self.failed,
                {"tool": self.tool_name},
            ),
            Metric(
                "siyarix_tool_duration_seconds",
                MetricType.GAUGE,
                self.total_duration_seconds,
                {"tool": self.tool_name},
            ),
        ]


@dataclass
class PlannerMetrics:
    """Planner-specific metrics."""
    plans_generated: int = 0
    plans_successful: int = 0
    plans_failed: int = 0
    model_calls: int = 0
    model_errors: int = 0
    interpreter_fallbacks: int = 0
    
    def to_metrics(self) -> list[Metric]:
        """Convert to Prometheus metrics."""
        return [
            Metric("siyarix_plans_generated", MetricType.COUNTER, self.plans_generated),
            Metric("siyarix_plans_successful", MetricType.GAUGE, self.plans_successful),
            Metric("siyarix_plans_failed", MetricType.GAUGE, self.plans_failed),
            Metric("siyarix_model_calls", MetricType.COUNTER, self.model_calls),
            Metric("siyarix_model_errors", MetricType.COUNTER, self.model_errors),
            Metric("siyarix_interpreter_fallbacks", MetricType.COUNTER, self.interpreter_fallbacks),
        ]


class MetricsCollector:
    """Centralized metrics collection."""
    
    _instance: MetricsCollector | None = None
    
    def __init__(self) -> None:
        self.execution = ExecutionMetrics()
        self.planner = PlannerMetrics()
        self.tools: dict[str, ToolMetrics] = {}
        self.start_time = time.time()
    
    @classmethod
    def instance(cls) -> MetricsCollector:
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def uptime_seconds(self) -> float:
        """Get uptime since startup."""
        return time.time() - self.start_time
    
    def record_scan(self, duration: float, successful: bool, findings_count: int = 0) -> None:
        """Record scan execution."""
        self.execution.total_scans += 1
        if successful:
            self.execution.successful_scans += 1
        else:
            self.execution.failed_scans += 1
        
        self.execution.total_duration_seconds += duration
        self.execution.average_duration_seconds = (
            self.execution.total_duration_seconds / self.execution.total_scans
        )
        self.execution.total_findings += findings_count
    
    def record_tool_execution(
        self,
        tool_name: str,
        duration: float,
        successful: bool,
        findings_count: int = 0,
    ) -> None:
        """Record tool execution."""
        if tool_name not in self.tools:
            self.tools[tool_name] = ToolMetrics(tool_name=tool_name)
        
        tool = self.tools[tool_name]
        tool.executions += 1
        if successful:
            tool.successful += 1
        else:
            tool.failed += 1
        
        tool.total_duration_seconds += duration
        tool.findings_count += findings_count
    
    def record_plan_generation(self, successful: bool, used_model: bool = False) -> None:
        """Record plan generation."""
        self.planner.plans_generated += 1
        if successful:
            self.planner.plans_successful += 1
        else:
            self.planner.plans_failed += 1
        
        if used_model:
            self.planner.model_calls += 1
    
    def record_model_error(self) -> None:
        """Record model provider error."""
        self.planner.model_errors += 1
    
    def record_interpreter_fallback(self) -> None:
        """Record fallback to interpreter."""
        self.planner.interpreter_fallbacks += 1
    
    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = [
            "# HELP siyarix_uptime Uptime in seconds",
            "# TYPE siyarix_uptime gauge",
            f"siyarix_uptime {self.uptime_seconds()}",
            "",
        ]
        
        # Execution metrics
        for metric in self.execution.to_metrics():
            lines.append(f"# HELP {metric.name} Execution metric")
            lines.append(f"# TYPE {metric.name} {metric.type}")
            lines.append(metric.to_prometheus())
            lines.append("")
        
        # Tool metrics
        for tool_metrics in self.tools.values():
            for metric in tool_metrics.to_metrics():
                lines.append(f"# HELP {metric.name} Tool metric")
                lines.append(f"# TYPE {metric.name} {metric.type}")
                lines.append(metric.to_prometheus())
                lines.append("")
        
        # Planner metrics
        for metric in self.planner.to_metrics():
            lines.append(f"# HELP {metric.name} Planner metric")
            lines.append(f"# TYPE {metric.name} {metric.type}")
            lines.append(metric.to_prometheus())
            lines.append("")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Export metrics as dictionary."""
        return {
            "uptime_seconds": self.uptime_seconds(),
            "execution": {
                "total_scans": self.execution.total_scans,
                "successful_scans": self.execution.successful_scans,
                "failed_scans": self.execution.failed_scans,
                "total_findings": self.execution.total_findings,
                "avg_duration_seconds": self.execution.average_duration_seconds,
            },
            "planner": {
                "plans_generated": self.planner.plans_generated,
                "plans_successful": self.planner.plans_successful,
                "plans_failed": self.planner.plans_failed,
                "model_calls": self.planner.model_calls,
                "model_errors": self.planner.model_errors,
                "interpreter_fallbacks": self.planner.interpreter_fallbacks,
            },
            "tools": {
                name: {
                    "executions": tool.executions,
                    "successful": tool.successful,
                    "failed": tool.failed,
                    "findings_count": tool.findings_count,
                }
                for name, tool in self.tools.items()
            },
        }


def get_metrics() -> MetricsCollector:
    """Get metrics collector instance."""
    return MetricsCollector.instance()
