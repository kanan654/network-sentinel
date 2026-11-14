from src.detection.port_scan import PortScanDetector
from src.detection.syn_flood import SynFloodDetector
from src.detection.traffic_spike import TrafficSpikeDetector
from src.detection.repeated_connections import RepeatedConnectionDetector


SOURCE = "192.168.1.100"
DESTINATION = "192.0.2.10"


def show_result(scenario, alert):
    if alert:
        print(f"[ALERT] {scenario}")
        print(f"  Event    : {alert['event']}")
        print(f"  Severity : {alert['severity']}")
        print(f"  Details  : {alert['details']}")
        return True

    print(f"[NO ALERT] {scenario}")
    return False


def simulate_normal_traffic():
    print("\n========== NORMAL TRAFFIC ==========")

    port_detector = PortScanDetector(threshold=5)
    syn_detector = SynFloodDetector(threshold=8)
    traffic_detector = TrafficSpikeDetector(threshold=8)
    connection_detector = RepeatedConnectionDetector(threshold=5)

    results = [
        port_detector.detect(SOURCE, DESTINATION, 80),
        port_detector.detect(SOURCE, DESTINATION, 443),
        port_detector.detect(SOURCE, DESTINATION, 8080),
    ]

    for _ in range(3):
        results.append(
            syn_detector.detect(SOURCE, DESTINATION, 0x02)
        )
        results.append(
            traffic_detector.detect(SOURCE, DESTINATION)
        )
        results.append(
            connection_detector.detect(SOURCE, DESTINATION, 0x02)
        )

    assert all(result is None for result in results)

    print("[PASS] Normal traffic generated no alerts.")
    return True


def simulate_port_scan():
    print("\n========== PORT SCAN SIMULATION ==========")

    detector = PortScanDetector(threshold=5)

    alert = None

    for port in [21, 22, 23, 80, 443]:
        alert = detector.detect(SOURCE, DESTINATION, port)

    detected = show_result("Port Scan", alert)

    duplicate = detector.detect(SOURCE, DESTINATION, 8080)

    assert detected
    assert duplicate is None

    print("[PASS] Port scan detected. Duplicate suppressed.")
    return True


def simulate_syn_flood():
    print("\n========== SYN FLOOD SIMULATION ==========")

    detector = SynFloodDetector(threshold=8)

    alert = None

    for _ in range(8):
        alert = detector.detect(SOURCE, DESTINATION, 0x02)

    detected = show_result("SYN Flood Pattern", alert)

    duplicate = detector.detect(SOURCE, DESTINATION, 0x02)

    assert detected
    assert duplicate is None

    print("[PASS] SYN flood pattern detected. Duplicate suppressed.")
    return True


def simulate_traffic_spike():
    print("\n========== TRAFFIC SPIKE SIMULATION ==========")

    detector = TrafficSpikeDetector(threshold=8)

    alert = None

    for _ in range(8):
        alert = detector.detect(SOURCE, DESTINATION)

    detected = show_result("Traffic Spike", alert)

    duplicate = detector.detect(SOURCE, DESTINATION)

    assert detected
    assert duplicate is None

    print("[PASS] Traffic spike detected. Duplicate suppressed.")
    return True


def simulate_repeated_connections():
    print("\n========== REPEATED CONNECTION SIMULATION ==========")

    detector = RepeatedConnectionDetector(threshold=5)

    alert = None

    for _ in range(5):
        alert = detector.detect(SOURCE, DESTINATION, 0x02)

    detected = show_result("Repeated Connection Attempts", alert)

    duplicate = detector.detect(SOURCE, DESTINATION, 0x02)

    assert detected
    assert duplicate is None

    print("[PASS] Repeated connections detected. Duplicate suppressed.")
    return True


def main():
    print("=" * 55)
    print("             NETWORK SENTINEL")
    print("       CONTROLLED ATTACK SIMULATOR")
    print("=" * 55)

    scenarios = [
        simulate_normal_traffic,
        simulate_port_scan,
        simulate_syn_flood,
        simulate_traffic_spike,
        simulate_repeated_connections,
    ]

    passed = 0

    for scenario in scenarios:
        if scenario():
            passed += 1

    print("\n" + "=" * 55)
    print(f"SIMULATION RESULTS: {passed}/{len(scenarios)} PASSED")
    print("=" * 55)

    if passed == len(scenarios):
        print("[SUCCESS] All simulation scenarios passed.")
    else:
        raise SystemExit("[FAILURE] One or more scenarios failed.")


if __name__ == "__main__":
    main()
