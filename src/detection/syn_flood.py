import time
from collections import defaultdict, deque


class SynFloodDetector:

    def __init__(self, threshold=100, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.syn_records = defaultdict(deque)
        self.alerted_destinations = {}

    def detect(self, source_ip, destination_ip, tcp_flags):

        current_time = time.time()

        syn = bool(tcp_flags & 0x02)
        ack = bool(tcp_flags & 0x10)

        if not syn or ack:
            return None

        key = (source_ip, destination_ip)
        records = self.syn_records[key]

        while records and current_time - records[0] > self.time_window:
            records.popleft()

        if not records:
            self.alerted_destinations.pop(key, None)

        records.append(current_time)

        if len(records) >= self.threshold:

            if key not in self.alerted_destinations:

                self.alerted_destinations[key] = current_time

                return {
                    "detected": True,
                    "event": "POSSIBLE_SYN_FLOOD",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "syn_count": len(records),
                    "severity": "CRITICAL",
                    "details": (
                        f"{len(records)} SYN packets within "
                        f"{self.time_window} seconds"
                    )
                }

        return None
