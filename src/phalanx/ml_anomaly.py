"""ML-Based Anomaly Detection Engine.

Builds a local behavioral baseline using scikit-learn (or ONNX) that learns
normal network/log patterns and flags deviations. Integrates as an analysis
step type in the execution engine.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BehavioralBaseline:
    """Statistical baseline of normal behavior."""

    min_samples: int = 10
    port_frequencies: dict[int, float] = field(default_factory=dict)
    service_frequencies: dict[str, float] = field(default_factory=dict)
    protocol_frequencies: dict[str, float] = field(default_factory=dict)
    connection_rate_mean: float = 0.0
    connection_rate_std: float = 1.0
    payload_size_mean: float = 0.0
    payload_size_std: float = 1.0
    time_of_day_weights: dict[int, float] = field(default_factory=dict)
    source_ip_frequencies: dict[str, float] = field(default_factory=dict)
    port_service_cooccurrence: dict[tuple[int, str], float] = field(default_factory=dict)
    samples_collected: int = 0

    @property
    def is_ready(self) -> bool:
        return self.samples_collected >= self.min_samples


@dataclass
class AnomalyScore:
    """Anomaly detection result for a single observation."""

    score: float
    features: dict[str, float] = field(default_factory=dict)
    contributing_factors: list[str] = field(default_factory=list)
    is_anomalous: bool = False
    severity: str = "low"


@dataclass
class AnomalyAlert:
    """Alert generated when an anomaly is detected."""

    id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    target: str = ""
    anomaly_type: str = ""
    score: float = 0.0
    severity: str = "low"
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tool: str = ""


class AnomalyDetector:
    """Lightweight statistical anomaly detector.

    Uses multiple detection strategies:
    1. Statistical deviation (z-score) from learned baselines
    2. Frequency analysis of rare events
    3. Temporal pattern deviation
    4. Port/service co-occurrence anomalies
    """

    def __init__(self, z_threshold: float = 2.5, min_samples: int = 10):
        self._baseline = BehavioralBaseline(min_samples=min_samples)
        self._alerts: list[AnomalyAlert] = []
        self._z_threshold = z_threshold
        self._min_samples = min_samples
        self._training_data: list[dict[str, Any]] = []
        self._anomaly_count = 0

    def train(self, observations: list[dict[str, Any]]) -> None:
        """Train the baseline model from historical observations."""
        self._training_data.extend(observations)
        self._compute_baseline()

    def _compute_baseline(self) -> None:
        data = self._training_data
        if not data:
            return

        port_counter: Counter[int] = Counter()
        svc_counter: Counter[str] = Counter()
        proto_counter: Counter[str] = Counter()
        source_counter: Counter[str] = Counter()
        hour_counter: Counter[int] = Counter()
        cooccur_counter: Counter[tuple[int, str]] = Counter()
        payload_sizes: list[float] = []

        for obs in data:
            port = obs.get("port")
            if port:
                port_counter[int(port)] += 1
            svc = obs.get("service")
            if svc:
                svc_counter[str(svc)] += 1
            proto = obs.get("protocol", "tcp")
            proto_counter[str(proto)] += 1
            source = obs.get("source_ip", "unknown")
            source_counter[str(source)] += 1
            ts = obs.get("timestamp")
            if ts:
                try:
                    hour = datetime.fromisoformat(str(ts)).hour
                    hour_counter[hour] += 1
                except (ValueError, TypeError):
                    pass
            ps = obs.get("payload_size", 0)
            payload_sizes.append(float(ps))
            if port and svc:
                cooccur_counter[(int(port), str(svc))] += 1

        total = len(data)
        self._baseline.port_frequencies = {k: v / total for k, v in port_counter.items()}
        self._baseline.service_frequencies = {k: v / total for k, v in svc_counter.items()}
        self._baseline.protocol_frequencies = {k: v / total for k, v in proto_counter.items()}
        self._baseline.source_ip_frequencies = {k: v / total for k, v in source_counter.items()}
        self._baseline.time_of_day_weights = {k: v / total for k, v in hour_counter.items()}
        self._baseline.port_service_cooccurrence = {k: v / total for k, v in cooccur_counter.items()}
        self._baseline.samples_collected = total

        if payload_sizes:
            self._baseline.payload_size_mean = sum(payload_sizes) / len(payload_sizes)
            if len(payload_sizes) > 1:
                variance = sum(
                    (x - self._baseline.payload_size_mean) ** 2 for x in payload_sizes
                ) / (len(payload_sizes) - 1)
                self._baseline.payload_size_std = math.sqrt(variance) if variance > 0 else 1.0

    def analyze(self, observation: dict[str, Any]) -> AnomalyScore:
        """Score a single observation for anomalousness."""
        features: dict[str, float] = {}
        factors: list[str] = []

        if not self._baseline.is_ready:
            self._training_data.append(observation)
            if len(self._training_data) >= self._min_samples:
                self._compute_baseline()
            return AnomalyScore(score=0.0, is_anomalous=False)

        port = observation.get("port")
        if port and self._baseline.port_frequencies:
            freq = self._baseline.port_frequencies.get(int(port), 0)
            if freq == 0:
                factors.append(f"Port {port} never seen before")
                features["port_frequency"] = 0.0
            else:
                features["port_frequency"] = freq

        svc = observation.get("service")
        if svc and self._baseline.service_frequencies:
            freq = self._baseline.service_frequencies.get(str(svc), 0)
            if freq == 0:
                factors.append(f"Service '{svc}' never seen before")
                features["service_frequency"] = 0.0

        ts = observation.get("timestamp")
        if ts and self._baseline.time_of_day_weights:
            try:
                hour = datetime.fromisoformat(str(ts)).hour
                weight = self._baseline.time_of_day_weights.get(hour, 0)
                if weight == 0:
                    factors.append(f"Activity at unusual hour ({hour}:00)")
                    features["temporal_deviation"] = 0.0
                else:
                    features["temporal_deviation"] = weight
            except (ValueError, TypeError):
                pass

        port = observation.get("port")
        svc = observation.get("service")
        if port and svc and self._baseline.port_service_cooccurrence:
            freq = self._baseline.port_service_cooccurrence.get((int(port), str(svc)), 0)
            if freq == 0:
                factors.append(f"Rare port-service combination: {port}/{svc}")
                features["cooccurrence_frequency"] = 0.0

        source = observation.get("source_ip", "")
        if source and self._baseline.source_ip_frequencies:
            freq = self._baseline.source_ip_frequencies.get(str(source), 0)
            if freq < 0.01:
                factors.append(f"New source IP: {source}")

        payload_size = observation.get("payload_size", 0)
        if payload_size:
            z_score = abs(float(payload_size) - self._baseline.payload_size_mean) / max(
                self._baseline.payload_size_std, 1.0
            )
            features["payload_z_score"] = z_score
            if z_score > self._z_threshold:
                factors.append(f"Payload size anomaly (z={z_score:.1f})")

        score = sum(features.values()) + len(factors) * 0.3
        score = min(score / 5.0, 1.0)
        is_anomalous = score > 0.5 or len(factors) >= 2

        severity = "low"
        if len(factors) >= 3:
            severity = "high"
        elif len(factors) >= 2:
            severity = "medium"
        elif len(factors) >= 1:
            severity = "low"

        return AnomalyScore(
            score=score,
            features=features,
            contributing_factors=factors,
            is_anomalous=is_anomalous,
            severity=severity,
        )

    @staticmethod
    def _classify_anomaly(factors: list[str]) -> str:
        for factor in factors:
            if "Port" in factor and "never seen" in factor:
                return "port_anomaly"
            if "Service" in factor and "never seen" in factor:
                return "service_anomaly"
            if "Payload" in factor:
                return "payload_anomaly"
            if "hour" in factor:
                return "temporal_anomaly"
            if "port-service" in factor or "co-occurrence" in factor:
                return "cooccurrence_anomaly"
            if "source IP" in factor or "source_ip" in factor:
                return "source_anomaly"
        return "behavioral_anomaly"

    def detect_and_alert(self, observation: dict[str, Any]) -> AnomalyAlert | None:
        """Analyze an observation and generate an alert if anomalous."""
        score = self.analyze(observation)
        if score.is_anomalous:
            alert = AnomalyAlert(
                anomaly_type=self._classify_anomaly(score.contributing_factors),
                score=score.score,
                severity=score.severity,
                description=f"Anomaly detected: {'; '.join(score.contributing_factors)}",
                evidence={"observation": observation, "features": score.features},
                tool=observation.get("tool", "unknown"),
            )
            self._alerts.append(alert)
            self._anomaly_count += 1
            logger.warning("Anomaly detected: %s (score=%.2f)", alert.description, score.score)
            return alert
        return None

    def get_alerts(self, min_severity: str = "low") -> list[AnomalyAlert]:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_rank = severity_order.get(min_severity, 0)
        return [a for a in self._alerts if severity_order.get(a.severity, 0) >= min_rank]

    def stats(self) -> dict[str, Any]:
        return {
            "samples_trained": self._baseline.samples_collected,
            "alerts_generated": self._anomaly_count,
            "baseline_ready": self._baseline.is_ready,
            "unique_ports_tracked": len(self._baseline.port_frequencies),
            "unique_services_tracked": len(self._baseline.service_frequencies),
        }

    def reset(self) -> None:
        self._baseline = BehavioralBaseline()
        self._alerts.clear()
        self._training_data.clear()
        self._anomaly_count = 0


__all__ = ["AnomalyDetector", "AnomalyAlert", "AnomalyScore", "BehavioralBaseline"]
