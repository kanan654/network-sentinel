import time
from collections import defaultdict, deque


class RepeatedConnectionDetector:

    def __init__(self, threshold=20, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.connection_records = defaultdict(deque)
        self.alerted_connections = set()

    def detect(self, source_ip, destination_ip, tcp_flags):

        syn = bool(tcp_flags & 0x02)
        ack = bool(tcp_flags & 0x10)

        # Only count initial TCP connection attempts.
        if not syn or ack:
            return None

        current_time = time.time()
        key = (source_ip, destination_ip)
        records = self.connection_records[key]

        while records and current_time - records[0] > self.time_window:
            records.popleft()

        if not records:
            self.alerted_connections.discard(key)

        records.append(current_time)

        if len(records) >= self.threshold:
            if key not in self.alerted_connections:
                self.alerted_connections.add(key)

                return {
                    "detected": True,
                    "event": "REPEATED_CONNECTION_ATTEMPTS",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "severity": "MEDIUM",
                    "attempt_count": len(records),
                    "details": (
                        f"{len(records)} SYN attempts within "
                        f"{self.time_window} seconds"
                    )
                }

        return None
