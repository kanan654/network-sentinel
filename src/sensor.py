import os
import time
import queue
import threading

import httpx
from scapy.all import sniff, IP, TCP, UDP, ICMP


# ==========================================
# CONFIGURATION
# ==========================================

API_URL = os.getenv(
    "SENSOR_API_URL",
    "https://network-sentinel.onrender.com"
).rstrip("/") + "/api/sensor/packets"

API_KEY = os.getenv("SENSOR_API_KEY")
INTERFACE = os.getenv("SENSOR_INTERFACE", "eth0")

BATCH_SIZE = 200
BATCH_INTERVAL = 1

packet_queue = queue.Queue(maxsize=10000)


# ==========================================
# PACKET CAPTURE
# ==========================================

def capture_packet(packet):

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    data = {
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": [],
        "icmp_type": None,
        "icmp_code": None
    }

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        data["protocol"] = "TCP"
        data["source_port"] = tcp.sport
        data["destination_port"] = tcp.dport

        flag_map = {
            "FIN": 0x01,
            "SYN": 0x02,
            "RST": 0x04,
            "PSH": 0x08,
            "ACK": 0x10,
            "URG": 0x20
        }

        flags = int(tcp.flags)

        data["tcp_flags"] = [
            name
            for name, value in flag_map.items()
            if flags & value
        ]

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        data["protocol"] = "UDP"
        data["source_port"] = udp.sport
        data["destination_port"] = udp.dport

    elif packet.haslayer(ICMP):

        icmp = packet[ICMP]

        data["protocol"] = "ICMP"
        data["icmp_type"] = int(icmp.type)
        data["icmp_code"] = int(icmp.code)

    try:
        packet_queue.put_nowait(data)
    except queue.Full:
        print("[WARNING] Packet queue full. Packet dropped.")


# ==========================================
# BATCH TRANSMISSION
# ==========================================

def send_batch(client, packets):

    payload = {"packets": packets}

    for attempt in range(3):

        try:
            response = client.post(
                API_URL,
                json=payload,
                headers={
                    "X-Sensor-Key": API_KEY
                }
            )

            response.raise_for_status()

            result = response.json()

            print(
                f"[SENT] {result['packets_processed']} packets "
                f"successfully processed by Render"
            )

            return True

        except httpx.HTTPError as error:

            print(
                f"[WARNING] Transmission attempt "
                f"{attempt + 1}/3 failed: {error}"
            )

            time.sleep(2 ** attempt)

    print(
        f"[ERROR] Batch permanently dropped: "
        f"{len(packets)} packets"
    )

    return False


def transmission_worker():

    print("[SENSOR] Transmission worker started")

    with httpx.Client(timeout=15.0) as client:

        while True:

            packets = []

            try:
                first_packet = packet_queue.get(timeout=1)
                packets.append(first_packet)

            except queue.Empty:
                continue

            while len(packets) < BATCH_SIZE:

                try:
                    packets.append(
                        packet_queue.get_nowait()
                    )

                except queue.Empty:
                    break

            send_batch(client, packets)


# ==========================================
# MAIN
# ==========================================

def main():

    if not API_KEY:
        raise RuntimeError(
            "SENSOR_API_KEY is missing. Configure it before starting."
        )

    print("=" * 55)
    print("             NETWORK SENTINEL SENSOR")
    print("=" * 55)

    print(f"[CONFIG] Interface: {INTERFACE}")
    print(f"[CONFIG] API: {API_URL}")
    print("[CONFIG] Payload capture: DISABLED")
    print("[CONFIG] Batch size:", BATCH_SIZE)

    worker = threading.Thread(
        target=transmission_worker,
        daemon=True
    )

    worker.start()

    print("[SENSOR] Starting packet capture...")
    print("[SENSOR] Press CTRL+C to stop.")

    try:

        sniff(
            iface=INTERFACE,
            prn=capture_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n[SENSOR] Stopping packet capture...")

    finally:

        print(
            f"[SENSOR] Remaining queued packets: "
            f"{packet_queue.qsize()}"
        )


if __name__ == "__main__":
    main()
