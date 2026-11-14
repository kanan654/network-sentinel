class RiskScorer:

    SEVERITY_WEIGHTS = {
        "LOW": 10,
        "MEDIUM": 30,
        "HIGH": 60,
        "CRITICAL": 85
    }

    THREAT_WEIGHTS = {
        "POSSIBLE_PORT_SCAN": 5,
        "POSSIBLE_SYN_FLOOD": 15,
        "UNUSUAL_TRAFFIC_SPIKE": 8,
        "REPEATED_CONNECTION_ATTEMPTS": 5
    }

    def score(
        self,
        event_type,
        severity,
        occurrence_count=1
    ):

        severity = severity.upper()

        if severity not in self.SEVERITY_WEIGHTS:
            raise ValueError("Invalid severity level")

        if (
            not isinstance(occurrence_count, int)
            or isinstance(occurrence_count, bool)
            or occurrence_count < 1
        ):
            raise ValueError("Occurrence count must be a positive integer")

        base_score = self.SEVERITY_WEIGHTS[severity]

        threat_weight = self.THREAT_WEIGHTS.get(
            event_type,
            0
        )

        recurrence_weight = min(
            (occurrence_count - 1) * 5,
            15
        )

        final_score = min(
            base_score + threat_weight + recurrence_weight,
            100
        )

        if final_score >= 80:
            risk_level = "CRITICAL"

        elif final_score >= 60:
            risk_level = "HIGH"

        elif final_score >= 30:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        return {
            "score": final_score,
            "risk_level": risk_level,
            "severity_weight": base_score,
            "threat_weight": threat_weight,
            "recurrence_weight": recurrence_weight
        }
