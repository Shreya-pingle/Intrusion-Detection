"""
anomaly_detector.py

Contains optimized, stateful anomaly detection functions that use a sliding window
technique for efficient, real-time analysis of network packets.
"""

import time
from custom_hashmap import CustomHashMap
from custom_queue import CustomQueue

# --- ANOMALY DETECTION CONSTANTS ---

# DOS_WINDOW: Time window in seconds to track packet frequency for DoS detection.
DOS_WINDOW = 60.0
# DOS_THRESHOLD: Number of packets from a single IP within the window to trigger a DoS alert.
DOS_THRESHOLD = 5

# PORTSCAN_WINDOW: Time window in seconds to track unique ports for port scan detection.
PORTSCAN_WINDOW = 10.0
# PORTSCAN_THRESHOLD: Number of unique ports accessed by a single IP within the window to trigger a port scan alert.
PORTSCAN_THRESHOLD = 3

# --- DOS ATTACK DETECTION ---

def check_dos_attack(src_ip: str, dos_tracker_map: CustomHashMap) -> dict | None:
    """
    Checks for a DoS attack from a source IP using a sliding window queue.

    This function maintains a queue of timestamps for each source IP. The sliding
    window is implemented by enqueueing the current timestamp and dequeueing any
    timestamps older than the DOS_WINDOW. This provides an efficient,
_Amortized O(1)_
    check, as list-scanning is avoided.

    Args:
        src_ip: The source IP address of the packet.
        dos_tracker_map: A CustomHashMap mapping source IPs to their timestamp queues.

    Returns:
        A dictionary with alert details if a DoS attack is detected, otherwise None.
    """
    current_time = time.time()

    # Get the timestamp queue for the source IP
    timestamp_queue = dos_tracker_map.get(src_ip)

    # If this is a new IP, create a new queue and store it
    if timestamp_queue is None:
        timestamp_queue = CustomQueue()
        dos_tracker_map.insert(src_ip, timestamp_queue)

    # Add the current timestamp to the queue
    timestamp_queue.enqueue(current_time)

    # Slide the window: remove timestamps older than the DOS_WINDOW
    while not timestamp_queue.is_empty() and (current_time - timestamp_queue.peek()) > DOS_WINDOW:
        timestamp_queue.dequeue()

    # If the packet count in the window exceeds the threshold, issue an alert
    current_count = len(timestamp_queue)
    if current_count > DOS_THRESHOLD:
        return {
            'type': 'dos',
            'src_ip': src_ip,
            'packet_count': current_count,
            'window_seconds': DOS_WINDOW
        }
    return None

# --- PORT SCAN DETECTION ---

def check_port_scan(src_ip: str, dest_port: int, port_tracker_map: CustomHashMap) -> dict | None:
    """
    Checks for a port scan from a source IP using a sliding window queue.

    This function tracks recent (port, timestamp) tuples for each source IP. The
    sliding window removes old tuples efficiently. By storing tuples, it can
    accurately count unique ports within the time window. The check runs in
_O(k)_
    where k is the number of items in the window, but the filtering is
_Amortized O(1)_.

    Args:
        src_ip: The source IP address of the packet.
        dest_port: The destination port of the packet.
        port_tracker_map: A CustomHashMap mapping IPs to their (port, timestamp) queues.

    Returns:
        A dictionary with alert details if a port scan is detected, otherwise None.
    """
    current_time = time.time()

    # Get the port-timestamp queue for the source IP
    port_tuple_queue = port_tracker_map.get(src_ip)

    # If this is a new IP, create a new queue and store it
    if port_tuple_queue is None:
        port_tuple_queue = CustomQueue()
        port_tracker_map.insert(src_ip, port_tuple_queue)

    # Add the current (port, timestamp) tuple to the queue
    port_tuple_queue.enqueue((dest_port, current_time))

    # Slide the window: remove tuples older than the PORTSCAN_WINDOW
    while not port_tuple_queue.is_empty() and (current_time - port_tuple_queue.peek()[1]) > PORTSCAN_WINDOW:
        port_tuple_queue.dequeue()

    # Count unique ports within the current window (O(k) operation)
    unique_ports = set(port for port, timestamp in port_tuple_queue)
    current_unique_count = len(unique_ports)

    # If the unique port count exceeds the threshold, issue an alert
    if current_unique_count > PORTSCAN_THRESHOLD:
        return {
            'type': 'port_scan',
            'src_ip': src_ip,
            'unique_ports': current_unique_count,
            'window_seconds': PORTSCAN_WINDOW
        }
    return None

