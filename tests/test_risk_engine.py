import pytest

from src.risk_engine import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def test_port_scan_risk_score(scorer):
    result = scorer.score(
        "POSSIBLE_PORT_SCAN",
        "HIGH"
    )

    assert result["score"] == 65
    assert result["risk_level"] == "HIGH"


def test_syn_flood_critical_score(scorer):
    result = scorer.score(
        "POSSIBLE_SYN_FLOOD",
        "CRITICAL"
    )

    assert result["score"] == 100
    assert result["risk_level"] == "CRITICAL"


def test_traffic_spike_score(scorer):
    result = scorer.score(
        "UNUSUAL_TRAFFIC_SPIKE",
        "MEDIUM"
    )

    assert result["score"] == 38
    assert result["risk_level"] == "MEDIUM"


def test_repeated_connections_score(scorer):
    result = scorer.score(
        "REPEATED_CONNECTION_ATTEMPTS",
        "MEDIUM"
    )

    assert result["score"] == 35
    assert result["risk_level"] == "MEDIUM"


def test_repeated_occurrences_increase_risk(scorer):
    first = scorer.score(
        "POSSIBLE_PORT_SCAN",
        "HIGH",
        occurrence_count=1
    )

    repeated = scorer.score(
        "POSSIBLE_PORT_SCAN",
        "HIGH",
        occurrence_count=3
    )

    assert repeated["score"] > first["score"]


def test_recurrence_weight_is_capped(scorer):
    result = scorer.score(
        "POSSIBLE_PORT_SCAN",
        "HIGH",
        occurrence_count=100
    )

    assert result["recurrence_weight"] == 15
    assert result["score"] == 80


def test_unknown_event_uses_severity_weight(scorer):
    result = scorer.score(
        "UNKNOWN_EVENT",
        "HIGH"
    )

    assert result["score"] == 60
    assert result["risk_level"] == "HIGH"


def test_invalid_severity_is_rejected(scorer):
    with pytest.raises(ValueError):
        scorer.score("PORT_SCAN", "EXTREME")


def test_invalid_occurrence_count_is_rejected(scorer):
    with pytest.raises(ValueError):
        scorer.score(
            "PORT_SCAN",
            "HIGH",
            occurrence_count=0
        )
