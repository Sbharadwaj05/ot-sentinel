#!/usr/bin/env python3
"""
OT Sentinel — Test: Mass Register Read / Recon (OT-SENTINEL-MOD-005)

Sends a burst of FC03 (Read Holding Registers) requests to cross the
50-in-5-minutes frequency threshold. Triggers Wazuh rule 200006.

Expected Wazuh Alert:
  Rule ID: 200006, Level: 6

Usage:
  python test_mass_read.py --target 192.168.56.10 --count 60
"""

import argparse
import json
import socket
import time
from datetime import datetime, timezone

try:
    from pymodbus.client import ModbusTcpClient

    HAS_PYMODBUS = True
except ImportError:
    HAS_PYMODBUS = False


def get_local_ip(target: str, port: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((target, port))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-005")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument(
        "--count", type=int, default=60, help="Number of reads (default: 60)"
    )
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)
    logs = []

    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(args.target, port=args.port, timeout=5)
            if client.connect():
                print(f"Sending {args.count} FC03 reads to {args.target}...")
                for i in range(args.count):
                    client.read_holding_registers(i * 10, 10)
                    if i % 10 == 0:
                        print(f"  {i}/{args.count}")
                client.close()
                print("Done.")
            else:
                print("Connection failed — generating log lines only")
        except Exception as e:
            print(f"Error: {e} — generating log lines only")

    for i in range(args.count):
        log_entry = {
            "protocol": "modbus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "source_port": 54321 + (i % 100),
            "destination_ip": args.target,
            "destination_port": args.port,
            "transaction_id": i + 1,
            "unit_id": 1,
            "function_code": 3,
            "function_name": "read_holding_registers",
            "reference_number": i * 10,
            "count": 10,
            "data": "",
            "event_type": "request",
            "error": None,
        }
        logs.append(json.dumps(log_entry))

    print(f"\nGenerated {len(logs)} log lines")
    print("Sample log line:")
    print(logs[0])
    print("--- Expected Alert ---")
    print("Rule: 200006 | Level: 6 | OT-SENTINEL-MOD-005")
    print(f"Threshold: 50 reads in 5 min → sent {args.count}")
    print("Feed all log lines to Wazuh via:")
    print(
        f"  python test_mass_read.py --target {args.target} --count {args.count} >> /var/ossec/logs/modbus/modbus_tap.log"
    )


if __name__ == "__main__":
    main()
