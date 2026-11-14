import json

from src.event_logger import SecurityEventLogger


def create_logger(tmp_path, cooldown=15):
    log_file = tmp_path / "security_events.jsonl"

    logger = SecurityEventLogger(
        log_file=str(log_file),
        cooldown=cooldown
    )

    return logger, log_file


def test_security_event_is_saved(tmp_path):
    logger, log_file = create_logger(tmp_path)

    event = logger.log_event(
        "POSSIBLE_PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Suspicious port activity",
        "HIGH"
    )

    assert event is not None
    assert log_file.exists()

    with open(log_file, encoding="utf-8") as file:
        saved_event = json.loads(file.readline())

    assert saved_event["event"] == "POSSIBLE_PORT_SCAN"
    assert saved_event["source_ip"] == "10.0.0.1"
    assert saved_event["destination_ip"] == "10.0.0.2"
    assert saved_event["severity"] == "HIGH"


def test_event_contains_timestamp(tmp_path):
    logger, _ = create_logger(tmp_path)

    event = logger.log_event(
        "TEST_EVENT",
        "10.0.0.1",
        "10.0.0.2",
        "Testing timestamp"
    )

    assert "timestamp" in event
    assert event["timestamp"].endswith("+00:00")


def test_duplicate_alert_is_suppressed(tmp_path):
    logger, log_file = create_logger(tmp_path)

    first = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Port scan detected"
    )

    second = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Port scan detected again"
    )

    assert first is not None
    assert second is None
    assert len(logger.events) == 1

    with open(log_file, encoding="utf-8") as file:
        assert len(file.readlines()) == 1


def test_different_destinations_are_tracked_independently(tmp_path):
    logger, _ = create_logger(tmp_path)

    first = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "First destination"
    )

    second = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.3",
        "Second destination"
    )

    assert first is not None
    assert second is not None
    assert len(logger.events) == 2


def test_alert_allowed_after_cooldown(tmp_path, monkeypatch):
    import src.event_logger as logger_module

    current_time = [100]

    monkeypatch.setattr(
        logger_module.time,
        "time",
        lambda: current_time[0]
    )

    logger, _ = create_logger(tmp_path, cooldown=15)

    first = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "First alert"
    )

    current_time[0] = 105

    second = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Duplicate alert"
    )

    current_time[0] = 116

    third = logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "New alert after cooldown"
    )

    assert first is not None
    assert second is None
    assert third is not None
    assert len(logger.events) == 2


def test_multiple_events_are_persisted(tmp_path):
    logger, log_file = create_logger(tmp_path)

    logger.log_event(
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Port scan",
        "HIGH"
    )

    logger.log_event(
        "SYN_FLOOD",
        "10.0.0.3",
        "10.0.0.4",
        "SYN flood",
        "CRITICAL"
    )

    with open(log_file, encoding="utf-8") as file:
        saved_events = [
            json.loads(line)
            for line in file
        ]

    assert len(saved_events) == 2
    assert saved_events[0]["event"] == "PORT_SCAN"
    assert saved_events[1]["event"] == "SYN_FLOOD"


def test_event_contains_risk_score(tmp_path):
    log_file = tmp_path / "security_events.jsonl"

    logger = SecurityEventLogger(
        log_file=str(log_file),
        cooldown=0
    )

    event = logger.log_event(
        event_type="POSSIBLE_PORT_SCAN",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        details="Suspicious port activity",
        severity="HIGH"
    )

    assert event["risk_score"] == 65
    assert event["risk_level"] == "HIGH"


def test_risk_data_is_saved_to_jsonl(tmp_path):
    import json

    log_file = tmp_path / "security_events.jsonl"

    logger = SecurityEventLogger(
        log_file=str(log_file),
        cooldown=0
    )

    logger.log_event(
        event_type="POSSIBLE_SYN_FLOOD",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        details="High SYN packet activity",
        severity="CRITICAL"
    )

    with open(log_file, "r", encoding="utf-8") as file:
        saved_event = json.loads(file.readline())

    assert saved_event["risk_score"] == 100
    assert saved_event["risk_level"] == "CRITICAL"


def test_logger_creates_correlated_incident(tmp_path):
    log_file = tmp_path / "security_events.jsonl"

    logger = SecurityEventLogger(
        log_file=str(log_file),
        cooldown=0
    )

    logger.log_event(
        "POSSIBLE_PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "Port scan detected",
        "HIGH"
    )

    logger.log_event(
        "POSSIBLE_SYN_FLOOD",
        "10.0.0.1",
        "10.0.0.2",
        "SYN flood pattern detected",
        "CRITICAL"
    )

    assert len(logger.incidents) == 1
    assert logger.incidents[0]["event_count"] == 2
    assert logger.incidents[0]["highest_risk_score"] == 100
    assert (tmp_path / "incidents.jsonl").exists()
