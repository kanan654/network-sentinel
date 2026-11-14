import json
import os
import time

from datetime import datetime, timezone
from collections import Counter, defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ICMP

from src.detection.port_scan import PortScanDetector
from src.detection.syn_flood import SynFloodDetector
from src.detection.traffic_spike import TrafficSpikeDetector
from src.detection.repeated_connections import RepeatedConnectionDetector
from src.event_logger import SecurityEventLogger


# ==========================================
# NETWORK SENTINEL CONFIGURATION
# ==========================================

INTERFACE = "eth0"
CAPTURE_DURATION = 60

TIME_WINDOW = 10

PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 30
TRAFFIC_SPIKE_THRESHOLD = 100
CONNECTION_ATTEMPT_THRESHOLD = 20

ALERT_COOLDOWN = 15

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
EVENT_LOG = os.path.join(LOG_DIR, "security_events.jsonl")

os.makedirs(LOG_DIR, exist_ok=True)

event_logger = SecurityEventLogger(
    log_file=EVENT_LOG,
    cooldown=ALERT_COOLDOWN
)


# ==========================================
# DETECTION MODULE INITIALIZATION
# ==========================================

port_scan_detector = PortScanDetector(
    threshold=PORT_SCAN_THRESHOLD,
    time_window=TIME_WINDOW
)

syn_flood_detector = SynFloodDetector(
    threshold=SYN_FLOOD_THRESHOLD,
    time_window=TIME_WINDOW
)

traffic_spike_detector = TrafficSpikeDetector(
    threshold=TRAFFIC_SPIKE_THRESHOLD,
    time_window=TIME_WINDOW
)

repeated_connection_detector = RepeatedConnectionDetector(
    threshold=CONNECTION_ATTEMPT_THRESHOLD,
    time_window=TIME_WINDOW
)


# ==========================================
# TRAFFIC STATISTICS
# ==========================================

traffic_stats = Counter()
tcp_flag_stats = Counter()
port_stats = Counter()

ip_stats = defaultdict(lambda: {
    "sent": 0,
    "received": 0
})




alert_history = {}


# ==========================================
# TIME WINDOW CLEANUP
# ==========================================

def clean_old_events(activity, current_time):

    while activity and current_time - activity[0][0] > TIME_WINDOW:
        activity.popleft()


# ==========================================
# THREAT DETECTION ENGINE
# ==========================================

def detect_threats(source_ip, destination_ip, packet):

    # 1. Traffic Spike Detection
    spike_alert = traffic_spike_detector.detect(
        source_ip,
        destination_ip
    )

    if spike_alert:
        event_logger.log_event(
            spike_alert["event"],
            source_ip,
            destination_ip,
            spike_alert["details"],
            spike_alert["severity"]
        )

    # Remaining detectors require TCP packets.
    if not packet.haslayer(TCP):
        return

    tcp_layer = packet[TCP]
    flags = int(tcp_layer.flags)

    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)

    # 2. SYN Flood Detection
    syn_alert = syn_flood_detector.detect(
        source_ip,
        destination_ip,
        flags
    )

    if syn_alert:
        event_logger.log_event(
            syn_alert["event"],
            source_ip,
            destination_ip,
            syn_alert["details"],
            syn_alert["severity"]
        )

    # 3. Port Scan Detection
    if syn and not ack:
        port_alert = port_scan_detector.detect(
            source_ip,
            destination_ip,
            tcp_layer.dport
        )

        if port_alert:
            event_logger.log_event(
                port_alert["event"],
                source_ip,
                destination_ip,
                port_alert["details"],
                port_alert["severity"]
            )

    # 4. Repeated Connection Detection
    connection_alert = repeated_connection_detector.detect(
        source_ip,
        destination_ip,
        flags
    )

    if connection_alert:
        event_logger.log_event(
            connection_alert["event"],
            source_ip,
            destination_ip,
            connection_alert["details"],
            connection_alert["severity"]
        )


# ==========================================
# PACKET PROCESSING ENGINE
# ==========================================

def process_packet(packet):

    if not packet.haslayer(IP):

        traffic_stats["OTHER"] += 1
        traffic_stats["total_packets"] += 1

        return

    ip_layer = packet[IP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    packet_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": [],
        "icmp_type": None,
        "icmp_code": None,
        "packet_length": len(packet)
    }

    # --------------------------------------
    # TCP
    # --------------------------------------

    if packet.haslayer(TCP):

        tcp_layer = packet[TCP]

        packet_data["protocol"] = "TCP"
        packet_data["source_port"] = tcp_layer.sport
        packet_data["destination_port"] = tcp_layer.dport

        flags = int(tcp_layer.flags)

        flag_map = {
            "SYN": 0x02,
            "ACK": 0x10,
            "FIN": 0x01,
            "RST": 0x04,
            "PSH": 0x08,
            "URG": 0x20
        }

        for flag_name, flag_value in flag_map.items():

            if flags & flag_value:

                packet_data["tcp_flags"].append(flag_name)
                tcp_flag_stats[flag_name] += 1

        port_stats[tcp_layer.dport] += 1

    # --------------------------------------
    # UDP
    # --------------------------------------

    elif packet.haslayer(UDP):

        udp_layer = packet[UDP]

        packet_data["protocol"] = "UDP"
        packet_data["source_port"] = udp_layer.sport
        packet_data["destination_port"] = udp_layer.dport

        port_stats[udp_layer.dport] += 1

    # --------------------------------------
    # ICMP
    # --------------------------------------

    elif packet.haslayer(ICMP):

        icmp_layer = packet[ICMP]

        packet_data["protocol"] = "ICMP"
        packet_data["icmp_type"] = icmp_layer.type
        packet_data["icmp_code"] = icmp_layer.code

    # --------------------------------------
    # UPDATE STATISTICS
    # --------------------------------------

    protocol = packet_data["protocol"]

    traffic_stats["total_packets"] += 1
    traffic_stats[protocol] += 1

    ip_stats[source_ip]["sent"] += 1
    ip_stats[destination_ip]["received"] += 1

    # --------------------------------------
    # DISPLAY PACKET
    # --------------------------------------

    print("\n----- PACKET DETECTED -----")

    for key, value in packet_data.items():
        print(f"{key}: {value}")

    # --------------------------------------
    # RUN THREAT DETECTION
    # --------------------------------------

    detect_threats(source_ip, destination_ip, packet)


# ==========================================
# FINAL TRAFFIC SUMMARY
# ==========================================

def display_summary():

    print("\n")
    print("=" * 55)
    print("             NETWORK SENTINEL SUMMARY")
    print("=" * 55)

    print("\n[TRAFFIC STATISTICS]")

    for protocol, count in traffic_stats.items():
        print(f"{protocol}: {count}")

    print("\n[TCP FLAG STATISTICS]")

    for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
        print(f"{flag}: {tcp_flag_stats[flag]}")

    print("\n[TOP DESTINATION PORTS]")

    for port, count in port_stats.most_common(10):
        print(f"Port {port}: {count} packets")

    print("\n[IP COMMUNICATION STATISTICS]")

    for ip, stats in ip_stats.items():

        print(
            f"{ip} | Sent: {stats['sent']} | "
            f"Received: {stats['received']}"
        )

    print("\n[SECURITY EVENTS]")

    if event_logger.events:

        for event in event_logger.events:

            print(
                f"{event['event']} | "
                f"{event['source_ip']} | "
                f"{event['severity']}"
            )

    else:
        print("No suspicious activity detected.")

    print("\nTotal Security Events:", len(event_logger.events))
    print("\nEvent log location:", EVENT_LOG)

    print("=" * 55)
    print("             CAPTURE COMPLETED")
    print("=" * 55)


# ==========================================
# MAIN APPLICATION
# ==========================================

def main():

    print("=" * 55)
    print("              NETWORK SENTINEL")
    print("       INTELLIGENT THREAT MONITORING")
    print("=" * 55)

    print("Monitoring Interface:", INTERFACE)
    print("Capture Duration:", CAPTURE_DURATION, "seconds")
    print("Detection Window:", TIME_WINDOW, "seconds")

    print("\nThreat Detection Modules:")
    print("- Port Scan Detection")
    print("- SYN Flood Detection")
    print("- Traffic Spike Detection")
    print("- Repeated Connection Monitoring")
    print("- Security Event Logging")

    print("\nWaiting for network packets...\n")

    try:

        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
            timeout=CAPTURE_DURATION
        )

    except KeyboardInterrupt:

        print("\nCapture stopped by user.")

    except Exception as error:

        print("\nCAPTURE ERROR:", error)

    finally:

        display_summary()


if __name__ == "__main__":
    main()
