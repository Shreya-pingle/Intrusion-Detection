"""
data_loader.py

Handles loading and parsing of network packet data from a CSV file.

This script defines a `PacketInfo` dataclass to represent individual packets and
provides a function `load_packets_from_csv` to read a CSV file, parse its rows
into PacketInfo objects, and return them as a list.
"""

import csv
from pathlib import Path
from dataclasses import dataclass

@dataclass
class PacketInfo:
    """Stores information about a single network packet."""
    src_ip: str
    dest_ip: str
    protocol: str
    payload: str
    length: int
    dest_port: int = 0

def load_packets_from_csv(filename: Path, limit: int = 1000) -> list[PacketInfo]:
    """Loads packet data from a CSV file with robust error handling."""
    packets = []
    try:
        with open(filename, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            try:
                next(reader)  # Skip header row
            except StopIteration:
                return []  # File is empty
            for row in reader:
                if len(packets) >= limit:
                    break
                if len(row) != 9:
                    continue  # Skip malformed rows
                try:
                    (
                        _,
                        src_ip,
                        dest_ip,
                        protocol,
                        src_port,
                        dest_port,
                        length_str,
                        payload,
                        _,
                    ) = row

                    if payload == "NaN":
                        payload = ""

                    # Parse destination port; handle blanks and non-numeric values
                    try:
                        dest_port_val = int(float(dest_port)) if dest_port else 0
                    except (ValueError, TypeError):
                        dest_port_val = 0

                    packets.append(PacketInfo(
                        src_ip=src_ip,
                        dest_ip=dest_ip,
                        protocol=protocol,
                        payload=payload,
                        length=int(length_str),
                        dest_port=dest_port_val
                    ))
                except (ValueError, IndexError):
                    # Catch errors from unpacking or int conversion
                    continue
    except FileNotFoundError:
        print(f"Error: Unable to open file at '{filename}'.")
    return packets
