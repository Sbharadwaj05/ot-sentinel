#!/usr/bin/env python3
"""
OT Sentinel — Test: Modbus on Non-Standard Port (OT-SENTINEL-MOD-008)

Generates a log line showing Modbus traffic on port 1502 instead of 502.
Triggers Wazuh rule 200011.

Expected Wazuh Alert:
  Rule ID: 200011, Level: 4

Usage:
  python test_nonstandard_port.py --target 192.168.56.10 --port 1502
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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-008")
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--port", type=int, default=1502, help="Non-standard port (default: 1502)"
    )
    args = parser.parse_args()

    source_ip = get_local_ip(
        args.target, 502
    )  # Get IP via standard port, but log via non-standard

    log_entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": 54321,
        "destination_ip": args.target,
        "destination_port": args.port,  # Non-502 port
        "transaction_id": 1,
        "unit_id": 1,
        "function_code": 3,
        "function_name": "read_holding_registers",
        "reference_number": 0,
        "count": 1,
        "data": "",
        "event_type": "request",
        "error": None,
    }

    print(f"Target: {args.target}:{args.port} (non-standard)")
    print(f"Source IP: {source_ip}")
    print(json.dumps(log_entry))
    print("--- Expected Alert ---")
    print("Rule: 200011 | Level: 4 | OT-SENTINEL-MOD-008")
    print("Modbus traffic on non-502 port detected")


if __name__ == "__main__":
    main()
