"""
main.py

Terminal-based runner for the Intrusion Detection System.

This script loads network packets from a CSV file, processes them one by one, and
runs them through a signature-based detector and a stateful, time-based anomaly
detector to identify potential threats.
"""

import time
from pathlib import Path
import datetime
from custom_queue import CustomQueue
from data_loader import load_packets_from_csv, PacketInfo
from custom_hashmap import CustomHashMap
from anomaly_detector import check_dos_attack, check_port_scan
from signature_db import setup_signature_database

# --- CONFIGURATION CONSTANTS ---

# SIMULATION_SPEED: The delay in seconds between processing each packet.
SIMULATION_SPEED = 0.05
# PACKET_LIMIT: The total number of packets to load from the dataset.
PACKET_LIMIT = 4000
# DATASET_FILENAME: The name of the CSV file containing the packet data.
DATASET_FILENAME = "demo_features_DEMO.csv"


def run_tests():
    """Runs unit tests for the CustomQueue."""
    print("--- Running Queue Tests ---")
    q = CustomQueue()
    try:
        q.dequeue()
    except IndexError as e:
        print(f"[PASS] Dequeue from empty queue raises: {e}")
    q.enqueue(85)
    print(f"[PASS] Enqueued 85 as an element, peek = {q.peek()}")
    print(f"[PASS] Dequeued = {q.dequeue()}")
    for i in range(1, 6):
        q.enqueue(i)
    fifo_ok = True
    for i in range(1, 6):
        val = q.dequeue()
        if val != i:
            print(f"[FAIL] Expected {i} got {val}")
            fifo_ok = False
    if fifo_ok:
        print("[PASS] FIFO order preserved")
    try:
        q.peek()
    except IndexError as e:
        print(f"[PASS] Peek from empty queue raises: {e}")
    print("--- Queue Tests Finished ---\n")


def run_signature_detector(packet_info: PacketInfo, signature_map: CustomHashMap) -> dict | None:
    """Checks a single packet for malicious signatures and returns an alert dict."""
    payload = packet_info.payload
    if not payload:
        return None

    attack_name = signature_map.get(payload)
    if attack_name is not None:
        return {
            'type': 'signature',
            'attack_type': attack_name,
            'src_ip': packet_info.src_ip,
            'payload': payload
        }
    return None


def format_alert_for_logging(alert_dict: dict) -> str:
    """Formats an alert dictionary into a standardized log string."""
    timestamp = datetime.datetime.now().isoformat()
    log_type = alert_dict.get('type', 'UNKNOWN').upper()
    src_ip = alert_dict.get('src_ip', 'N/A')
    
    details = ""
    if log_type == 'DOS':
        details = f"Count: {alert_dict.get('packet_count')} in {alert_dict.get('window_seconds')}s"
    elif log_type == 'PORT_SCAN':
        details = f"Unique Ports: {alert_dict.get('unique_ports')} in {alert_dict.get('window_seconds')}s"
    elif log_type == 'SIGNATURE':
        details = f"Attack: {alert_dict.get('attack_type')}, Payload: {alert_dict.get('payload')}"
        
    return f"[{timestamp}] - [{log_type}] - Source IP: {src_ip} | Details: {details}"


def main():
    """Main function to run the packet processing application."""
    run_tests()

    print("--- Starting Packet Processing with Signature + Time-Based Anomaly Detection ---")
    packet_queue = CustomQueue()
    log_queue = CustomQueue()

    # --- 1. Initialize Detection Systems ---
    # Create signature database using CustomHashMap
    signature_db = setup_signature_database()
    print(f"Signature database loaded with {len(signature_db)} attack patterns.")
    # Create time-based tracking maps for anomaly detection
    dos_tracker_map = CustomHashMap()  # key=IP, value=CustomQueue of timestamps
    port_tracker_map = CustomHashMap() # key=IP, value=CustomQueue of (port, timestamp) tuples

    # --- 2. Load Packets ---
    script_dir = Path(__file__).resolve().parent
    csv_path = script_dir / DATASET_FILENAME
    packets = load_packets_from_csv(csv_path, limit=PACKET_LIMIT)

    if not packets:
        print("No packets were loaded. Exiting.")
        return

    for pkt in packets:
        packet_queue.enqueue(pkt)

    print(f"Initial queue size: {len(packet_queue)}.")
    print("--- Processing Packets ---")

    # --- 3. Process Packet Queue ---
    malicious_count = 0
    packets_with_payload = 0

    while not packet_queue.is_empty():
        pkt = packet_queue.dequeue()

        # Run signature-based detection
        signature_alert = run_signature_detector(pkt, signature_db)
        if signature_alert:
            print(f"🚨 ALERT: Malicious payload detected! Type: {signature_alert['attack_type']}, Source IP: {signature_alert['src_ip']}")
            log_queue.enqueue(format_alert_for_logging(signature_alert))
            malicious_count += 1

        # Run time-based anomaly detection (DoS)
        dos_alert = check_dos_attack(pkt.src_ip, dos_tracker_map)
        if dos_alert:
            print(f"🚨 ALERT: Potential DoS/Flood from {dos_alert['src_ip']} ({dos_alert['packet_count']} packets in {dos_alert['window_seconds']}s)")
            log_queue.enqueue(format_alert_for_logging(dos_alert))
            malicious_count += 1

        # Run time-based anomaly detection (Port Scan)
        if pkt.protocol == 'TCP' and pkt.dest_port and pkt.dest_port > 0:
            port_scan_alert = check_port_scan(pkt.src_ip, pkt.dest_port, port_tracker_map)
            if port_scan_alert:
                print(f"🚨 ALERT: Potential Port Scan by {port_scan_alert['src_ip']} ({port_scan_alert['unique_ports']} unique ports in {port_scan_alert['window_seconds']}s)")
                log_queue.enqueue(format_alert_for_logging(port_scan_alert))
                malicious_count += 1

        # Optional: Print packet info for debugging
        if pkt.payload:
            packets_with_payload += 1
            print(f"Processed packet: {pkt.src_ip} -> {pkt.dest_ip} | Proto: {pkt.protocol} | Payload: '{pkt.payload}'")

        # Simulate real-time processing delay
        time.sleep(SIMULATION_SPEED)

    print("--- Packet Processing Finished ---")
    print(f"Final queue size: {len(packet_queue)}.")
    print(f"Total malicious events detected: {malicious_count}.")
    print(f"Packets with payloads checked for signatures: {packets_with_payload}.")

    # --- 4. Write Buffered Logs to File ---
    print("\n--- Writing Alerts to Log File ---")
    LOG_FILENAME = "alerts.log"
    with open(LOG_FILENAME, 'a', encoding='utf-8') as f:
        while not log_queue.is_empty():
            log_message = log_queue.dequeue()
            f.write(log_message + "\n")
    print(f"All alerts saved to {LOG_FILENAME}")


if __name__ == "__main__":
    main()