# DS-Course_Project

# Hybrid Intrusion Detection System (IDS) with Optimized Anomaly Detection

**Status:** Complete (Version 1.0)

This project is a high-performance Hybrid Intrusion Detection System (IDS) built in Python. It simulates a real-time network environment, processing a stream of packets to detect multiple attack types:

1.  **Signature-Based:** Detects known attack patterns (e.g., SQLi, XSS).
2.  **Anomaly-Based:** Detects behavioral deviations (e.g., DoS floods, Port Scans).

The core of this project is the **effective use of custom-built data structures** (`CustomHashMap` and `CustomQueue`) to achieve high-speed, efficient detection and logging, demonstrating solutions to real-world performance bottlenecks.

-----

## Features

  * **Hybrid Detection Engine:** Combines stateless signature-based detection with stateful, time-based anomaly detection.
  * **Signature-Based Detector:** Uses a `CustomHashMap` for **O(1) average-time** lookups of known malicious payloads (SQL Injection, XSS, Command Injection, etc.).
  * **Optimized Anomaly Detector:**
      * Detects **Denial-of-Service (DoS)** floods.
      * Detects **Port Scan** reconnaissance.
      * Uses a **`CustomQueue` Sliding Window** for detection, providing an **Amortized O(1)** time complexity for filtering—a massive improvement over a naive `O(k)` list scan.
  * **Dynamic `CustomHashMap`:** The `CustomHashMap` features automatic resizing (rehashing) based on a load factor, ensuring it maintains `O(1)` average-time performance even as the number of tracked IPs grows.
  * **Dual Interface:**
    1.  **Terminal Version (`main.py`):** A lightweight, terminal-only runner for testing and processing.
    2.  **Web UI (`app.py`):** A Flask web server with a real-time dashboard that uses Server-Sent Events (SSE) to stream alerts to the browser.
  * **Asynchronous Logging:** Uses a `CustomQueue` as a non-blocking log buffer (a Producer-Consumer pattern). The high-speed detection loop (`O(1)`) enqueues log messages, while a separate, low-priority thread/process handles the slow file I/O, ensuring no alerts are missed.

-----

## System Architecture & Effective Data Structure Use

This project was built to demonstrate how to solve complex performance problems by selecting the *right* data structure for the job.

### 1\. `CustomHashMap`: For High-Speed Lookups (O(1))

The `CustomHashMap` (built with chaining and resizing) is used in two key places:

  * **Signature Database (`signature_db`):**
      * **Problem:** Checking every packet's payload against a list of 10+ rules would be an `O(k)` operation *for every packet*.
      * **Solution:** By storing rules in a hash map, we get **O(1) average-time** lookups. This is *thousands* of times faster and the only viable solution for a real-time system.
  * **IP Trackers (`dos_tracker_map`, `port_tracker_map`):**
      * **Problem:** We need to track the "state" (packet timestamps, ports visited) for *every unique IP address*.
      * **Solution:** A hash map allows us to retrieve the correct IP's tracking data (its `CustomQueue`) in **O(1) average-time**.

### 2\. `CustomQueue`: For Optimized Sliding Windows (Amortized O(1))

This is the project's main optimization, solving a major performance bottleneck.

  * **The Problem (Naive `list`-based approach):**
      * To check for a DoS attack (e.g., 400 packets in 5s), one might store timestamps in a `list`.
      * For *every new packet*, you would have to scan the *entire list* to filter out old timestamps. This is a **slow `O(k)` operation** (where `k` is the number of packets in the window).
  * **The Solution (Efficient `CustomQueue` Sliding Window):**
      * We store timestamps in a `CustomQueue`.
      * **1. `enqueue(time)`:** Add the new packet's time. **(O(1))**
      * **2. `while (time - peek()) > WINDOW`:** Check *only* the oldest item. **(O(1))**
      * **3. `dequeue()`:** If the oldest item is expired, remove it. **(O(1))**
      * This logic reduces the filtering cost from `O(k)` to **Amortized O(1)**, as each packet is only enqueued once and dequeued once.

### 3\. `CustomQueue`: For Asynchronous Logging (Producer-Consumer)

  * **The Problem:** Writing to a file (disk I/O) is a *slow, blocking operation*. If the main detection loop writes to a file, it will pause and miss new incoming packets.
  * **The Solution (Log Buffer):**
      * **Producer:** The main loop (`process_packets`) finds an alert, formats a log string, and `enqueue`s it into a `log_queue`. This is an instant **O(1)** operation.
      * **Consumer:** A separate, low-priority thread (`log_writer_thread`) runs in the background. It slowly and safely `dequeue`s messages from the queue and writes them to `alerts.log`.
      * This **decouples** the high-speed detection from the slow I/O, ensuring the system is robust and responsive.

-----

## How to Run

### Prerequisites

  * Python 3.x
  * Flask (`pip install Flask`)

### 1\. Terminal Version (Recommended for testing)

This will run the full simulation in your terminal and create the `alerts.log` file.

```bash
python main.py
```

### 2\. Web UI Version (Recommended for demo)

This starts the live dashboard.

**Step 1: Run the Flask Server**

```bash
python app.py
```

**Step 2: Open the Dashboard**
Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

**Step 3: Start the Simulation**
Click the "Start Simulation" button and watch the alerts appear in real-time.

-----

## Project Structure

```
.
├── app.py                # Flask Web UI server (with SSE)
├── main.py               # Terminal-based version
├── anomaly_detector.py   # Optimized sliding window logic (DoS, Port Scan)
├── signature_db.py       # Signature rule database
├── data_loader.py        # Loads and parses the CSV
├── custom_hashmap.py     # Custom HashMap implementation (with resizing)
├── custom_queue.py       # Custom Queue implementation (linked-list)
│
├── demo_features_DEMO.csv  # The packet dataset (4000 rows)
├── alerts.log            # The final output log file
└── README.md             # This file
```