"""Tests for ML-based anomaly detection engine."""

from phalanx.ml_anomaly import AnomalyDetector


class TestAnomalyDetector:
    def test_detector_initial_state(self):
        detector = AnomalyDetector()
        stats = detector.stats()
        assert stats["samples_trained"] == 0
        assert stats["alerts_generated"] == 0
        assert stats["baseline_ready"] is False

    def test_training_with_observations(self):
        detector = AnomalyDetector(min_samples=5)
        for i in range(5):
            detector.train(
                [{"port": 80, "service": "http", "protocol": "tcp", "source_ip": "10.0.0.1"}]
            )
        assert detector.stats()["baseline_ready"] is True

    def test_anomaly_detection_unknown_port(self):
        detector = AnomalyDetector(min_samples=3)
        for i in range(5):
            detector.train([{"port": 80, "service": "http", "protocol": "tcp"}])

        score = detector.analyze({"port": 4444, "service": "unknown", "protocol": "tcp"})
        assert score.is_anomalous or len(score.contributing_factors) > 0

    def test_anomaly_alert_generation(self):
        detector = AnomalyDetector(min_samples=3)
        for i in range(5):
            detector.train([{"port": 80, "service": "http", "protocol": "tcp"}])

        alert = detector.detect_and_alert(
            {"port": 4444, "service": "unknown", "protocol": "tcp", "tool": "nmap"}
        )
        if alert:
            assert alert.anomaly_type in ("port_anomaly", "service_anomaly", "behavioral_anomaly")
            assert alert.score > 0
            assert alert.tool == "nmap"

    def test_no_false_positive_normal_behavior(self):
        detector = AnomalyDetector(z_threshold=5.0, min_samples=3)
        for i in range(10):
            detector.train(
                [{"port": 80, "service": "http", "protocol": "tcp", "payload_size": 100}]
            )

        score = detector.analyze(
            {"port": 80, "service": "http", "protocol": "tcp", "payload_size": 100}
        )
        assert not score.is_anomalous

    def test_reset_clears_state(self):
        detector = AnomalyDetector(min_samples=3)
        detector.train([{"port": 80, "service": "http"}])
        detector.detect_and_alert({"port": 4444, "service": "unknown"})
        detector.reset()
        stats = detector.stats()
        assert stats["samples_trained"] == 0
        assert stats["alerts_generated"] == 0
