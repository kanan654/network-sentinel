from src.detection.syn_flood import SynFloodDetector


def test_normal_syn_traffic_does_not_trigger_alert():
    detector = SynFloodDetector(threshold=5, time_window=10)

    for i in range(4):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x02)

    assert result is None


def test_high_syn_traffic_triggers_alert():
    detector = SynFloodDetector(threshold=5, time_window=10)

    for i in range(5):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x02)

    assert result is not None
    assert result["event"] == "POSSIBLE_SYN_FLOOD"
    assert result["syn_count"] == 5


def test_non_syn_packets_are_ignored():
    detector = SynFloodDetector(threshold=5, time_window=10)

    for i in range(10):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x10)

    assert result is None


def test_syn_ack_packets_are_ignored():
    detector = SynFloodDetector(threshold=5, time_window=10)

    for i in range(10):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x12)

    assert result is None


def test_old_syn_activity_expires_after_time_window(monkeypatch):
    detector = SynFloodDetector(threshold=5, time_window=10)
    current_time = [100.0]

    monkeypatch.setattr(
        "src.detection.syn_flood.time.time",
        lambda: current_time[0]
    )

    for i in range(4):
        detector.detect("192.168.1.10", "192.0.2.1", 0x02)

    current_time[0] = 111.0

    for i in range(4):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x02)

    assert result is None


def test_different_source_ips_are_tracked_independently():
    detector = SynFloodDetector(threshold=5, time_window=10)

    for i in range(3):
        detector.detect("192.168.1.10", "192.0.2.1", 0x02)

    for i in range(3):
        result = detector.detect("192.168.1.20", "192.0.2.1", 0x02)

    assert result is None


def test_alert_is_not_repeated_for_same_detection_window():
    detector = SynFloodDetector(threshold=5, time_window=10)
    alerts = []

    for i in range(7):
        result = detector.detect("192.168.1.10", "192.0.2.1", 0x02)

        if result is not None:
            alerts.append(result)

    assert len(alerts) == 1
