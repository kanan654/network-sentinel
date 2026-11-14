from collections import defaultdict, deque
import time


class PortScanDetector:

    def __init__(self, threshold=15, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.port_activity = defaultdict(deque)
        self.alerted_connections = set()

    def detect(self, source_ip, destination_ip, destination_port):

        current_time = time.time()
        connection_key = (source_ip, destination_ip)

        activity = self.port_activity[connection_key]

        activity.append((current_time, destination_port))

        while activity and current_time - activity[0][0] > self.time_window:
            activity.popleft()

        unique_ports = {
            port for timestamp, port in activity
        }

        # Allow a fresh alert if activity falls below threshold.
        if len(unique_ports) < self.threshold:
            self.alerted_connections.discard(connection_key)

        if len(unique_ports) >= self.threshold:

            if connection_key not in self.alerted_connections:

                self.alerted_connections.add(connection_key)

                return {
                    "detected": True,
                    "event": "POSSIBLE_PORT_SCAN",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "severity": "HIGH",
                    "unique_ports": len(unique_ports),
                    "details": (
                        f"Access attempts to {len(unique_ports)} "
                        f"different TCP ports within "
                        f"{self.time_window} seconds"
                    )
                }

        return None
