"""Tests for the XI Predictor module."""

from __future__ import annotations

from phalanx.xi.predictor import Predictor, Prediction


class TestPredictor:
    """Test suite for the Predictive Action Engine."""

    def test_initial_state(self):
        p = Predictor()
        predictions = p.predict_next("idle")
        assert isinstance(predictions, list)
        assert len(predictions) > 0

    def test_phase_based_predictions(self):
        p = Predictor()
        predictions = p.predict_next("recon", target="example.com")
        assert any("nmap" in pred.action for pred in predictions)
        assert any(pred.confidence >= 0.7 for pred in predictions)

    def test_tool_followup_predictions(self):
        p = Predictor()
        predictions = p.predict_next("scanning", last_tool="nmap", target="example.com")
        assert any("nuclei" in pred.action for pred in predictions)
        assert any(pred.category == "suggestion" for pred in predictions)

    def test_findings_based_predictions(self):
        p = Predictor()
        predictions = p.predict_next("scanning", target="example.com", findings_count=3)
        assert any("report" in pred.action.lower() for pred in predictions)

    def test_learn_from_commands(self):
        p = Predictor()
        p.learn("nmap -sV target")
        p.learn("nuclei -u target")
        predictions = p.predict_next("scanning", last_tool="nuclei")
        assert len(predictions) > 0

    def test_sequence_learning(self):
        p = Predictor()
        for _ in range(3):
            p.learn("nmap -sV target")
            p.learn("nuclei -u target")
        predictions = p.predict_next("scanning", last_tool="nmap")
        assert any(pred.category == "optimization" for pred in predictions)

    def test_warning_when_no_findings(self):
        p = Predictor()
        predictions = p.predict_next("scanning", findings_count=0)
        assert any(pred.category == "warning" for pred in predictions)

    def test_no_warning_when_idle(self):
        p = Predictor()
        predictions = p.predict_next("idle", findings_count=0)
        warnings = [pred for pred in predictions if pred.category == "warning"]
        assert len(warnings) == 0

    def test_deduplication(self):
        p = Predictor()
        predictions = p.predict_next("idle")
        actions = [pred.action for pred in predictions]
        assert len(actions) == len(set(actions))

    def test_prediction_max_results(self):
        p = Predictor()
        predictions = p.predict_next("recon", last_tool="nmap", findings_count=5)
        assert len(predictions) <= 8

    def test_reset(self):
        p = Predictor()
        p.learn("nmap target")
        p.learn("nuclei target")
        p.reset()
        predictions = p.predict_next("idle")
        # Should still have phase-based defaults
        assert len(predictions) > 0

    def test_prediction_dataclass(self):
        pred = Prediction(
            action="nmap -sV target",
            confidence=0.85,
            reason="Recommended next step",
            category="suggestion",
            metadata={"source": "test"},
        )
        assert pred.action == "nmap -sV target"
        assert pred.confidence == 0.85
        assert pred.category == "suggestion"
        assert pred.metadata["source"] == "test"

    def test_confidence_sorting(self):
        p = Predictor()
        predictions = p.predict_next("scanning", last_tool="nmap", target="example.com")
        confidences = [pred.confidence for pred in predictions]
        assert confidences == sorted(confidences, reverse=True)
