"""SOC Agent.

Specializes in continuous log analysis, anomaly detection, and alert triage.
Upgraded with real-time log ingestion pipeline, pattern matching, and
automated triage ticket generation.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from phalanx.multi_agent import Agent, AgentRole

logger = logging.getLogger(__name__)


class SOCAgent(Agent):
    """Security Operations Center Agent.

    Capabilities:
    - Real-time syslog/windows event log analysis
    - Anomaly detection via pattern matching
    - Automated triage and ticket generation
    - Alert enrichment and correlation
    - MITRE ATT&CK mapping for detected events
    """

    def __init__(self, name: str = "soc-analyst-1") -> None:
        super().__init__(
            name=name,
            role=AgentRole.SOC,
            tools=["grep", "awk", "jq", "yq", "logstash", "filebeat"],
            description="Analyzes audit logs and security events for anomalies and generates triage tickets.",
        )
        self.set_task_handler(self._analyze_logs)
        self._alert_thresholds: dict[str, int] = {
            "failed_login": 5,
            "port_scan": 50,
            "malware_detected": 1,
            "privilege_escalation": 3,
            "data_exfil": 1,
            "webshell": 1,
        }
        self._detected_events: list[dict[str, Any]] = []
        self._tickets_generated: int = 0

    async def _analyze_logs(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        target = payload.get("target", "system")
        log_data = payload.get("logs", "")

        anomalies = self._detect_anomalies(log_data, target)
        triage = self._generate_triage(anomalies, target)
        mitre_mappings = self._map_to_mitre(anomalies)

        response = {
            "analysis": f"Completed SOC triage for {target}",
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies[:10],
            "triage_tickets": triage,
            "tickets_generated": len(triage),
            "mitre_attack_mappings": mitre_mappings[:5],
            "threat_level": self._assess_threat_level(anomalies),
            "recommendation": self._generate_recommendation(anomalies),
        }

        self._tickets_generated += len(triage)
        self._detected_events.extend(anomalies)
        logger.info(
            "SOC Agent: %d anomalies, %d tickets for %s", len(anomalies), len(triage), target
        )
        return response

    def _detect_anomalies(self, log_data: str, target: str) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        rules = self._load_detection_rules()

        for rule_name, rule in rules.items():
            pattern = rule["pattern"]
            severity = rule["severity"]
            matches = re.findall(pattern, log_data, re.IGNORECASE)
            count = len(matches)

            threshold = self._alert_thresholds.get(rule_name, 10)
            if count >= threshold:
                anomalies.append(
                    {
                        "rule": rule_name,
                        "severity": severity,
                        "count": count,
                        "target": target,
                        "threshold": threshold,
                        "description": rule["description"],
                        "timestamp": datetime.now().isoformat(),
                        "evidence": matches[:3],
                    }
                )
                logger.warning(
                    "SOC Alert [%s]: %s (count=%d, threshold=%d)",
                    severity,
                    rule_name,
                    count,
                    threshold,
                )

        return anomalies

    def _load_detection_rules(self) -> dict[str, Any]:
        return {
            "failed_login": {
                "pattern": r"(?i)(failed|invalid)\s+(login|password|authentication|auth)",
                "severity": "medium",
                "description": "Multiple failed authentication attempts detected",
            },
            "port_scan": {
                "pattern": r"(?i)(port\s*scan|nmap|masscan|SYN\s*scan|connection\s*attempt)",
                "severity": "low",
                "description": "Port scanning activity detected",
            },
            "malware_detected": {
                "pattern": r"(?i)(malware|virus|trojan|ransomware|backdoor|rootkit)",
                "severity": "critical",
                "description": "Malware signature detected in logs",
            },
            "privilege_escalation": {
                "pattern": r"(?i)(privilege\s*escalation|sudo\s+su|admin\s+access|elevation|UAC)",
                "severity": "high",
                "description": "Privilege escalation attempt detected",
            },
            "data_exfil": {
                "pattern": r"(?i)(exfil|data\s*leak|unauthorized\s*transfer|large\s*outbound)",
                "severity": "critical",
                "description": "Possible data exfiltration detected",
            },
            "bruteforce": {
                "pattern": r"(?i)(brute.?force|dictionary\s*attack|password\s*spray)",
                "severity": "high",
                "description": "Brute force attack pattern detected",
            },
            "webshell": {
                "pattern": r"(?i)(webshell|cmd\.aspx|shell\.php|eval\(|base64_decode)",
                "severity": "critical",
                "description": "Webshell activity detected",
            },
            "lateral_movement": {
                "pattern": r"(?i)(psexec|wmic|winrm|wmi|schtasks|remote\s+desktop)",
                "severity": "high",
                "description": "Lateral movement patterns detected",
            },
        }

    def _generate_triage(
        self, anomalies: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        tickets: list[dict[str, Any]] = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_anomalies = sorted(
            anomalies, key=lambda a: severity_order.get(a.get("severity", "low"), 4)
        )

        for anomaly in sorted_anomalies[:5]:
            ticket = {
                "ticket_id": f"SOC-{datetime.now().strftime('%Y%m%d')}-{len(tickets) + 1:04d}",
                "title": f"{anomaly['severity'].upper()}: {anomaly['description']} on {target}",
                "severity": anomaly["severity"],
                "status": "open",
                "created_at": datetime.now().isoformat(),
                "source": anomaly.get("rule", "unknown"),
                "evidence_count": anomaly.get("count", 0),
                "assigned_to": "SOC_analyst",
                "recommended_action": self._action_for_severity(anomaly["severity"]),
            }
            tickets.append(ticket)
        return tickets

    def _action_for_severity(self, severity: str) -> str:
        actions = {
            "critical": "Immediate containment and investigation required",
            "high": "Escalate to senior analyst within 1 hour",
            "medium": "Investigate within 4 hours during business hours",
            "low": "Log for periodic review",
        }
        return actions.get(severity, "Review and assess")

    def _map_to_mitre(self, anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        mitre_map = {
            "failed_login": {
                "attack_id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access",
            },
            "port_scan": {
                "attack_id": "T1046",
                "technique": "Network Service Discovery",
                "tactic": "Discovery",
            },
            "malware_detected": {
                "attack_id": "T1204",
                "technique": "User Execution",
                "tactic": "Execution",
            },
            "privilege_escalation": {
                "attack_id": "T1548",
                "technique": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
            },
            "data_exfil": {
                "attack_id": "T1048",
                "technique": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
            },
            "bruteforce": {
                "attack_id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access",
            },
            "webshell": {
                "attack_id": "T1505",
                "technique": "Server Software Component",
                "tactic": "Persistence",
            },
            "lateral_movement": {
                "attack_id": "T1210",
                "technique": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
            },
        }
        mappings = []
        for anomaly in anomalies:
            rule = anomaly.get("rule", "")
            if rule in mitre_map:
                mappings.append(mitre_map[rule])
        return mappings

    def _assess_threat_level(self, anomalies: list[dict[str, Any]]) -> str:
        if any(a.get("severity") == "critical" for a in anomalies):
            return "CRITICAL"
        if any(a.get("severity") == "high" for a in anomalies):
            return "HIGH"
        if anomalies:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendation(self, anomalies: list[dict[str, Any]]) -> str:
        if not anomalies:
            return "No action required; continue monitoring"
        sevs = {a.get("severity", "low") for a in anomalies}
        if "critical" in sevs:
            return "IMMEDIATE ACTION: Engage incident response team and isolate affected systems"
        if "high" in sevs:
            return "Escalate to senior analyst and begin investigation"
        return "Schedule for analysis during next review cycle"
