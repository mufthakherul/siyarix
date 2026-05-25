"""Tests for the XI ContextTracker module."""

from __future__ import annotations

from phalanx.xi.context_tracker import ContextTracker, OperationPhase


class TestContextTracker:
    """Test suite for ContextTracker."""

    def test_initial_state(self):
        tracker = ContextTracker()
        assert tracker.phase == OperationPhase.IDLE
        assert tracker.total_findings == 0
        assert tracker.command_count == 0
        assert tracker.targets == {}

    def test_set_phase(self):
        tracker = ContextTracker()
        tracker.set_phase(OperationPhase.SCANNING)
        assert tracker.phase == OperationPhase.SCANNING

    def test_auto_detect_phase_recon(self):
        tracker = ContextTracker()
        phase = tracker.auto_detect_phase("nmap", "scan target")
        assert phase == OperationPhase.SCANNING

    def test_auto_detect_phase_exploit(self):
        tracker = ContextTracker()
        phase = tracker.auto_detect_phase("sqlmap", "exploit target")
        assert phase == OperationPhase.EXPLOITATION

    def test_auto_detect_phase_reporting(self):
        tracker = ContextTracker()
        phase = tracker.auto_detect_phase("phalanx", "report findings")
        assert phase == OperationPhase.REPORTING

    def test_track_target(self):
        tracker = ContextTracker()
        target = tracker.track_target("192.168.1.1")
        assert target.address == "192.168.1.1"
        assert "192.168.1.1" in tracker.targets

    def test_track_target_duplicate(self):
        tracker = ContextTracker()
        t1 = tracker.track_target("192.168.1.1")
        t2 = tracker.track_target("192.168.1.1")
        assert t1 is t2

    def test_add_port(self):
        tracker = ContextTracker()
        tracker.add_port("192.168.1.1", 80, "http")
        target = tracker.targets["192.168.1.1"]
        assert 80 in target.open_ports
        assert "http" in target.services

    def test_add_port_duplicate(self):
        tracker = ContextTracker()
        tracker.add_port("192.168.1.1", 80, "http")
        tracker.add_port("192.168.1.1", 80, "http")
        target = tracker.targets["192.168.1.1"]
        assert len(target.open_ports) == 1

    def test_add_finding(self):
        tracker = ContextTracker()
        tracker.add_finding("192.168.1.1", "nmap")
        assert tracker.total_findings == 1
        target = tracker.targets["192.168.1.1"]
        assert target.findings_count == 1
        assert "nmap" in target.tools_used

    def test_record_execution(self):
        tracker = ContextTracker()
        tracker.record_execution("nmap", "192.168.1.1", 100.0, True, 3)
        assert tracker.command_count == 1
        assert tracker.total_findings == 3
        assert "192.168.1.1" in tracker.targets
        assert tracker.most_used_tools[0] == ("nmap", 1)

    def test_record_execution_failure(self):
        tracker = ContextTracker()
        tracker.record_execution("nmap", "192.168.1.1", 50.0, False, 0)
        recent = tracker.recent_executions
        assert len(recent) == 1
        assert recent[0].success is False

    def test_session_duration(self):
        tracker = ContextTracker()
        assert tracker.session_duration_seconds >= 0

    def test_summary_structure(self):
        tracker = ContextTracker()
        tracker.record_execution("nmap", "10.0.0.1", 100.0, True, 2)
        tracker.add_port("10.0.0.1", 443, "https")
        summary = tracker.summary()
        assert "phase" in summary
        assert "targets_count" in summary
        assert summary["total_findings"] == 2
        assert summary["commands_run"] == 1

    def test_suggest_next_phase(self):
        tracker = ContextTracker()
        tracker.set_phase(OperationPhase.RECON)
        assert tracker.suggest_next_phase() == OperationPhase.SCANNING

    def test_suggest_next_phase_last(self):
        tracker = ContextTracker()
        tracker.set_phase(OperationPhase.CLEANUP)
        assert tracker.suggest_next_phase() == OperationPhase.IDLE

    def test_reset(self):
        tracker = ContextTracker()
        tracker.record_execution("nmap", "10.0.0.1", 100.0, True, 2)
        tracker.reset()
        assert tracker.phase == OperationPhase.IDLE
        assert tracker.total_findings == 0
        assert tracker.command_count == 0
        assert tracker.targets == {}

    def test_most_used_tools_empty(self):
        tracker = ContextTracker()
        assert tracker.most_used_tools == []

    def test_recent_executions_limit(self):
        tracker = ContextTracker()
        for i in range(25):
            tracker.record_execution(f"tool{i}", "target", 10.0, True, 0)
        assert len(tracker.recent_executions) == 20


class TestOperationPhase:
    """Tests for OperationPhase utility."""

    def test_next_phase_sequence(self):
        assert OperationPhase.next_phase(OperationPhase.IDLE) == OperationPhase.RECON
        assert OperationPhase.next_phase(OperationPhase.RECON) == OperationPhase.SCANNING
        assert OperationPhase.next_phase(OperationPhase.SCANNING) == OperationPhase.ENUMERATION
        assert OperationPhase.next_phase(OperationPhase.EXPLOITATION) == OperationPhase.POST_EXPLOIT
        assert OperationPhase.next_phase(OperationPhase.REPORTING) == OperationPhase.CLEANUP

    def test_next_phase_unknown(self):
        assert OperationPhase.next_phase("unknown") == OperationPhase.IDLE
