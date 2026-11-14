from src.detection.traffic_spike import TrafficSpikeDetector


def test_no_alert_below_threshold():
    detector = TrafficSpikeDetector(threshold=3, time_window=10)

    assert detector.detect("10.0.0.1", "10.0.0.2") is None
    assert detector.detect("10.0.0.1", "10.0.0.2") is None


def test_alert_at_threshold():
    detector = TrafficSpikeDetector(threshold=3, time_window=10)

    detector.detect("10.0.0.1", "10.0.0.2")
    detector.detect("10.0.0.1", "10.0.0.2")

    alert = detector.detect("10.0.0.1", "10.0.0.2")

    assert alert is not None
    assert alert["event"] == "UNUSUAL_TRAFFIC_SPIKE"
    assert alert["severity"] == "MEDIUM"
    assert alert["packet_count"] == 3


def test_no_duplicate_alert_in_same_window():
    detector = TrafficSpikeDetector(threshold=2, time_window=10)

    detector.detect("10.0.0.1", "10.0.0.2")
    alert = detector.detect("10.0.0.1", "10.0.0.2")

    assert alert is not None

    duplicate = detector.detect("10.0.0.1", "10.0.0.2")

    assert duplicate is None
