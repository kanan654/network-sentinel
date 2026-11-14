from datetime import datetime, timezone

from src.incident_correlation import IncidentCorrelator


def make_event(source, event_type, score):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source,
        "event": event_type,
        "risk_score": score
    }


def test_first_event_does_not_create_incident():
    engine = IncidentCorrelator()

    result = engine.add_event(
        make_event("10.0.0.1", "POSSIBLE_PORT_SCAN", 65)
    )

    assert result is None


def test_related_events_create_incident():
    engine = IncidentCorrelator()

    engine.add_event(
        make_event("10.0.0.1", "POSSIBLE_PORT_SCAN", 65)
    )

    result = engine.add_event(
        make_event("10.0.0.1", "POSSIBLE_SYN_FLOOD", 100)
    )

    assert result["event_count"] == 2
    assert result["highest_risk_score"] == 100
    assert len(result["event_types"]) == 2


def test_different_sources_are_separated():
    engine = IncidentCorrelator()

    engine.add_event(
        make_event("10.0.0.1", "PORT_SCAN", 65)
    )

    result = engine.add_event(
        make_event("10.0.0.2", "SYN_FLOOD", 100)
    )

    assert result is None
