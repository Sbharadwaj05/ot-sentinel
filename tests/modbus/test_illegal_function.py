#!/usr/bin/env python3
"""
OT Sentinel — Test: Illegal Modbus Function Code (OT-SENTINEL-MOD-004)

Generates a log line with an illegal function code (FC 72 — reserved).
Should trigger Wazuh rule 200004.

Note: This test does NOT send a real Modbus packet with an illegal FC
(because pymodbus won't let you). It generates the JSON log line directly
for Wazuh ingestion.

Expected Wazuh Alert:
  Rule ID: 200004, Level: 8

Usage:
  python test_illegal_function.py --target 192.168.56.10
"""

import argparse
import json
import socket
from datetime import datetime, timezone


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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-004")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument(
        "--fc", type=int, default=72, help="Illegal function code (default: 72)"
    )
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)

    log_entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": 54321,
        "destination_ip": args.target,
        "destination_port": args.port,
        "transaction_id": 99,
        "unit_id": 1,
        "function_code": args.fc,
        "function_name": f"illegal_code_{args.fc}",
        "reference_number": 0,
        "count": 1,
        "data": "",
        "event_type": "request",
        "error": None,
    }

    print(f"Source IP: {source_ip}")
    print(f"Function Code: {args.fc} (illegal)")
    print(json.dumps(log_entry))
    print("--- Expected Alert ---")
    print("Rule: 200004 | Level: 8 | OT-SENTINEL-MOD-004")


if __name__ == "__main__":
    main()
