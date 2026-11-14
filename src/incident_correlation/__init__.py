from collections import defaultdict
from datetime import datetime, timezone


class IncidentCorrelator:

    def __init__(self, time_window=300):
        self.time_window = time_window
        self.incidents = defaultdict(list)

    def add_event(self, event):

        source_ip = event.get("source_ip")

        if not source_ip:
            return None

        now = datetime.now(timezone.utc)

        incident_events = self.incidents[source_ip]

        incident_events.append(event)

        self.incidents[source_ip] = [
            item for item in incident_events
            if (
                now - datetime.fromisoformat(
                    item["timestamp"]
                )
            ).total_seconds() <= self.time_window
        ]

        events = self.incidents[source_ip]

        if len(events) < 2:
            return None

        return {
            "incident_id": source_ip,
            "source_ip": source_ip,
            "event_count": len(events),
            "event_types": list(dict.fromkeys(
                item["event"] for item in events
            )),
            "highest_risk_score": max(
                item.get("risk_score", 0) for item in events
            ),
            "correlated_at": now.isoformat()
        }
