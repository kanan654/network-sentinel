
from src.detection.port_scan import PortScanDetector


def test_14_unique_ports_do_not_trigger_alert():

    detector = PortScanDetector(threshold=15, time_window=10)

    for port in range(1000, 1014):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    assert result is None


def test_15_unique_ports_trigger_alert():

    detector = PortScanDetector(threshold=15, time_window=10)

    for port in range(1000, 1015):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    assert result is not None
    assert result["event"] == "POSSIBLE_PORT_SCAN"
    assert result["unique_ports"] == 15
    assert result["severity"] == "HIGH"


def test_old_port_activity_expires_after_time_window(monkeypatch):

    detector = PortScanDetector(threshold=15, time_window=10)

    current_time = [100.0]

    monkeypatch.setattr(
        "src.detection.port_scan.time.time",
        lambda: current_time[0]
    )

    for port in range(1000, 1010):
        detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    current_time[0] = 111.0

    for port in range(2000, 2005):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    assert result is None


def test_repeated_access_to_same_port_does_not_trigger_alert():

    detector = PortScanDetector(threshold=15, time_window=10)

    for i in range(20):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            80
        )

    assert result is None


def test_different_source_ips_are_tracked_independently():

    detector = PortScanDetector(threshold=15, time_window=10)

    for port in range(1000, 1008):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    for port in range(2000, 2008):
        result = detector.detect(
            "192.168.1.20",
            "192.0.2.1",
            port
        )

    assert result is None


def test_different_destination_ips_are_tracked_independently():

    detector = PortScanDetector(threshold=15, time_window=10)

    for port in range(1000, 1008):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.1",
            port
        )

    for port in range(2000, 2008):
        result = detector.detect(
            "192.168.1.10",
            "192.0.2.2",
            port
        )

    assert result is None


def test_no_duplicate_alert_in_same_window():

    detector = PortScanDetector(threshold=3, time_window=10)

    detector.detect("192.168.1.10", "192.0.2.1", 80)
    detector.detect("192.168.1.10", "192.0.2.1", 81)

    alert = detector.detect("192.168.1.10", "192.0.2.1", 82)

    assert alert is not None

    duplicate = detector.detect("192.168.1.10", "192.0.2.1", 83)

    assert duplicate is None


def test_new_alert_after_old_activity_expires(monkeypatch):

    detector = PortScanDetector(threshold=3, time_window=10)

    current_time = [100.0]

    monkeypatch.setattr(
        "src.detection.port_scan.time.time",
        lambda: current_time[0]
    )

    for port in range(80, 83):
        alert = detector.detect("192.168.1.10", "192.0.2.1", port)

    assert alert is not None

    current_time[0] = 111.0

    for port in range(90, 93):
        alert = detector.detect("192.168.1.10", "192.0.2.1", port)

    assert alert is not None
    assert alert["event"] == "POSSIBLE_PORT_SCAN"


def test_no_duplicate_alert_in_same_window():

    detector = PortScanDetector(threshold=3, time_window=10)

    detector.detect("192.168.1.10", "192.0.2.1", 80)
    detector.detect("192.168.1.10", "192.0.2.1", 81)

    alert = detector.detect("192.168.1.10", "192.0.2.1", 82)

    assert alert is not None

    duplicate = detector.detect("192.168.1.10", "192.0.2.1", 83)

    assert duplicate is None


def test_new_alert_after_old_activity_expires(monkeypatch):

    detector = PortScanDetector(threshold=3, time_window=10)

    current_time = [100.0]

    monkeypatch.setattr(
        "src.detection.port_scan.time.time",
        lambda: current_time[0]
    )

    for port in range(80, 83):
        alert = detector.detect("192.168.1.10", "192.0.2.1", port)

    assert alert is not None

    current_time[0] = 111.0

    for port in range(90, 93):
        alert = detector.detect("192.168.1.10", "192.0.2.1", port)

    assert alert is not None
    assert alert["event"] == "POSSIBLE_PORT_SCAN"
