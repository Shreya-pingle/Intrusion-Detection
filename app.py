"""
app.py

Flask web server for the real-time Intrusion Detection System UI.

This application provides a web interface to visualize the packet processing and
alerting system. It uses Server-Sent Events (SSE) to stream live updates to the
frontend as packets are processed and threats are detected.
"""

from flask import Flask, render_template, Response, jsonify
import datetime
import json
import time
from pathlib import Path
from threading import Thread, Lock
from queue import Queue, Empty

# Import the logic from your other files
from custom_queue import CustomQueue
from data_loader import load_packets_from_csv, PacketInfo
from custom_hashmap import CustomHashMap
from anomaly_detector import check_dos_attack, check_port_scan
from signature_db import setup_signature_database

# --- FLASK APP and CONFIGURATION ---

app = Flask(__name__)

# SIMULATION_SPEED: The delay in seconds between processing each packet.
SIMULATION_SPEED = 0.05
# PACKET_LIMIT: The total number of packets to load from the dataset.
PACKET_LIMIT = 4000
# DATASET_FILENAME: The name of the CSV file containing the packet data.
DATASET_FILENAME = "demo_features_DEMO.csv"

# --- GLOBAL STATE MANAGEMENT ---

# Global state dictionary to track the simulation's progress.
# This is accessed by multiple threads, so a lock is required.
simulation_state = {
    'status': 'IDLE',           # Current status: IDLE, STARTING, MONITORING, FINISHED, ERROR
    'total_packets': 0,        # Total packets loaded for the simulation
    'processed_packets': 0,    # Number of packets processed so far
    'total_alerts': 0,         # Total alerts generated
    'is_running': False        # Flag to indicate if the simulation is active
}
state_lock = Lock() # Lock to ensure thread-safe access to the simulation_state

# Queue for Server-Sent Events (SSE) to communicate with the frontend.
event_queue = Queue()
# Queue for logging alerts to a file in a non-blocking way.
log_queue = Queue()

# --- LOGGING ---

LOG_FILENAME = "alerts.log"

# --- PACKET PROCESSING and DETECTION LOGIC ---

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
            'dest_ip': packet_info.dest_ip,
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


def process_packets():
    """Main packet processing loop that runs in a background thread."""
    global simulation_state

    with state_lock:
        simulation_state['status'] = 'MONITORING'
        simulation_state['is_running'] = True

    # --- 1. Initialize Detection Systems ---
    signature_db = setup_signature_database()
    dos_tracker_map = CustomHashMap()
    port_tracker_map = CustomHashMap()
    packet_queue = CustomQueue()

    # --- 2. Load Packets ---
    script_dir = Path(__file__).resolve().parent
    csv_path = script_dir / DATASET_FILENAME
    packets = load_packets_from_csv(csv_path, limit=PACKET_LIMIT)

    if not packets:
        with state_lock:
            simulation_state['status'] = 'ERROR'
            simulation_state['is_running'] = False
        event_queue.put({'type': 'error', 'message': 'Failed to load packets.'})
        return

    for pkt in packets:
        packet_queue.enqueue(pkt)

    with state_lock:
        simulation_state['total_packets'] = len(packet_queue)

    event_queue.put({'type': 'status', 'status': 'MONITORING', 'total_packets': len(packet_queue)})

    # --- 3. Process Packet Queue ---
    while not packet_queue.is_empty():
        # Check if the simulation has been stopped from another thread (optional)
        with state_lock:
            if not simulation_state['is_running']:
                break
        
        pkt = packet_queue.dequeue()

        with state_lock:
            simulation_state['processed_packets'] += 1
            current_processed = simulation_state['processed_packets']
            total = simulation_state['total_packets']

        # Run all detection mechanisms
        signature_alert = run_signature_detector(pkt, signature_db)
        dos_alert = check_dos_attack(pkt.src_ip, dos_tracker_map)
        port_scan_alert = None
        if pkt.protocol == 'TCP' and pkt.dest_port and pkt.dest_port > 0:
            port_scan_alert = check_port_scan(pkt.src_ip, pkt.dest_port, port_tracker_map)

        # --- 4. Send Alerts and Progress Updates ---
        alerts_found = [alert for alert in [signature_alert, dos_alert, port_scan_alert] if alert]
        if alerts_found:
            with state_lock:
                simulation_state['total_alerts'] += len(alerts_found)
            for alert in alerts_found:
                event_queue.put({'type': 'alert', 'data': alert})
                log_queue.put(format_alert_for_logging(alert))

        # Send progress update to the frontend
        event_queue.put({
            'type': 'progress',
            'processed': current_processed,
            'total': total,
            'alerts': simulation_state['total_alerts']
        })

        time.sleep(SIMULATION_SPEED)

    # --- 5. Finalize Simulation ---
    with state_lock:
        simulation_state['status'] = 'FINISHED'
        simulation_state['is_running'] = False

    event_queue.put({
        'type': 'status',
        'status': 'FINISHED',
        'processed': simulation_state['processed_packets'],
        'alerts': simulation_state['total_alerts']
    })

def log_writer_thread():
    """A dedicated thread to write logs from the queue to a file."""
    while True:
        # This blocks until a message is ready
        log_message = log_queue.get()
        with open(LOG_FILENAME, 'a', encoding='utf-8') as f:
            f.write(log_message + "\n")
        log_queue.task_done()

# --- FLASK ROUTES ---

@app.route('/')
def index():
    """Serves the main index.html page."""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_simulation():
    """Starts the packet processing simulation in a background thread."""
    global simulation_state

    with state_lock:
        if simulation_state['is_running']:
            return jsonify({'error': 'Simulation is already running.'}), 400

        # Reset the global state for a new run
        simulation_state = {
            'status': 'STARTING',
            'total_packets': 0,
            'processed_packets': 0,
            'total_alerts': 0,
            'is_running': True
        }

    # Start the packet processing in a daemon thread
    thread = Thread(target=process_packets, daemon=True)
    thread.start()

    return jsonify({'message': 'Simulation started successfully.'})

@app.route('/status')
def get_status():
    """Returns the current status of the simulation."""
    with state_lock:
        return jsonify(simulation_state)

@app.route('/stream')
def stream():
    """SSE endpoint to stream live events to the frontend."""
    def event_stream():
        while True:
            try:
                # Blocking call to wait for a new event
                event = event_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
            except Empty:
                # Send a heartbeat comment to keep the connection alive
                yield ": heartbeat\n\n"

    return Response(event_stream(), mimetype='text/event-stream')

if __name__ == '__main__':
    # Start the log writer thread. It's a daemon, so it will exit when the main app exits.
    log_thread = Thread(target=log_writer_thread, daemon=True)
    log_thread.start()

    app.run(debug=True, threaded=True, port=5000)
