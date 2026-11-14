import json
import os
import time

from datetime import datetime, timezone

from src.risk_engine import RiskScorer
from src.incident_correlation import IncidentCorrelator


class SecurityEventLogger:

    def __init__(self, log_file, cooldown=15):

        self.log_file = log_file
        self.cooldown = cooldown

        self.events = []
        self.listeners = []
        self.incidents = []
        self.alert_history = {}

        self.risk_scorer = RiskScorer()
        self.incident_correlator = IncidentCorrelator()

        log_directory = os.path.dirname(
            os.path.abspath(log_file)
        )

        os.makedirs(log_directory, exist_ok=True)

        self.incident_file = os.path.join(
            log_directory,
            "incidents.jsonl"
        )

    def add_listener(self, callback):
        if callback not in self.listeners:
            self.listeners.append(callback)

    def remove_listener(self, callback):
        if callback in self.listeners:
            self.listeners.remove(callback)

    def log_event(
        self,
        event_type,
        source_ip,
        destination_ip,
        details,
        severity="MEDIUM"
    ):

        current_time = time.time()

        event_key = (
            event_type,
            source_ip,
            destination_ip
        )

        last_alert = self.alert_history.get(event_key, 0)

        if current_time - last_alert < self.cooldown:
            return None

        risk = self.risk_scorer.score(
            event_type=event_type,
            severity=severity,
            occurrence_count=1
        )

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "event": event_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "severity": severity.upper(),
            "risk_score": risk["score"],
            "risk_level": risk["risk_level"],
            "details": details
        }

        # Correlate this event with previous events.
        incident = self.incident_correlator.add_event(event)

        if incident:
            event["incident"] = incident

            self.incidents.append(incident)

            with open(
                self.incident_file,
                "a",
                encoding="utf-8"
            ) as file:
                file.write(json.dumps(incident) + "\n")

            print("\n[INCIDENT CORRELATED]")
            print("Source IP:", incident["source_ip"])
            print("Related Events:", incident["event_types"])
            print("Event Count:", incident["event_count"])
            print("Highest Risk:", incident["highest_risk_score"])

        with open(
            self.log_file,
            "a",
            encoding="utf-8"
        ) as file:
            file.write(json.dumps(event) + "\n")

        self.alert_history[event_key] = current_time
        self.events.append(event)

        for listener in list(self.listeners):
            try:
                listener(event)
            except Exception as error:
                print("Event listener error:", error)

        print("\n" + "!" * 55)
        print("             SECURITY ALERT DETECTED")
        print("!" * 55)
        print("Event:", event["event"])
        print("Source IP:", event["source_ip"])
        print("Destination IP:", event["destination_ip"])
        print("Severity:", event["severity"])
        print("Risk Score:", event["risk_score"], "/ 100")
        print("Risk Level:", event["risk_level"])
        print("Details:", event["details"])
        print("!" * 55)

        return event
