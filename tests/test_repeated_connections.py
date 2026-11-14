from src.detection.repeated_connections import RepeatedConnectionDetector


def test_non_syn_packet_is_ignored():
    detector = RepeatedConnectionDetector(threshold=2)

    # ACK flag only
    assert detector.detect("10.0.0.1", "10.0.0.2", 0x10) is None


def test_alert_at_connection_threshold():
    detector = RepeatedConnectionDetector(threshold=3)

    detector.detect("10.0.0.1", "10.0.0.2", 0x02)
    detector.detect("10.0.0.1", "10.0.0.2", 0x02)

    alert = detector.detect("10.0.0.1", "10.0.0.2", 0x02)

    assert alert is not None
    assert alert["event"] == "REPEATED_CONNECTION_ATTEMPTS"
    assert alert["severity"] == "MEDIUM"
    assert alert["attempt_count"] == 3


def test_acknowledged_syn_is_ignored():
    detector = RepeatedConnectionDetector(threshold=2)

    # SYN + ACK is not an initial connection attempt.
    assert detector.detect("10.0.0.1", "10.0.0.2", 0x12) is None
