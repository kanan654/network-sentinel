import time
from collections import defaultdict, deque


class TrafficSpikeDetector:

    def __init__(self, threshold=100, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.packet_records = defaultdict(deque)
        self.alerted_sources = set()

    def detect(self, source_ip, destination_ip):

        current_time = time.time()
        records = self.packet_records[source_ip]

        while records and current_time - records[0] > self.time_window:
            records.popleft()

        if not records:
            self.alerted_sources.discard(source_ip)

        records.append(current_time)

        if len(records) >= self.threshold:
            if source_ip not in self.alerted_sources:
                self.alerted_sources.add(source_ip)

                return {
                    "detected": True,
                    "event": "UNUSUAL_TRAFFIC_SPIKE",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "severity": "MEDIUM",
                    "packet_count": len(records),
                    "details": (
                        f"{len(records)} packets from source "
                        f"within {self.time_window} seconds"
                    )
                }

        return None
