#!/usr/bin/env python3
"""
OT Sentinel — Test: Rogue Modbus Master (OT-SENTINEL-MOD-003)

Simulates a Modbus read from a source IP not in the known_modbus_masters
CDB list. Should trigger Wazuh rule 200003.

Expected Wazuh Alert:
  Rule ID: 200003, Level: 10
  Description: "OT Sentinel: Rogue Modbus master detected"

Usage:
  python test_rogue_master.py --target 192.168.56.10 --port 502
"""

import argparse
import json
import socket
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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-003")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=502)
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)
    status = "simulated"

    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(args.target, port=args.port, timeout=5)
            if client.connect():
                client.read_coils(0, 1)  # Any read will do
                status = "success"
            else:
                status = "connection_failed"
            client.close()
        except Exception as e:
            status = f"exception: {e}"

    log_entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": 54321,
        "destination_ip": args.target,
        "destination_port": args.port,
        "transaction_id": 1,
        "unit_id": 1,
        "function_code": 1,
        "function_name": "read_coils",
        "reference_number": 0,
        "count": 1,
        "data": "",
        "event_type": "request",
        "error": None,
    }

    print(f"Status: {status}")
    print(f"Source IP: {source_ip}")
    print(json.dumps(log_entry))
    print("--- Expected Alert ---")
    print("Rule: 200003 | Level: 10 | OT-SENTINEL-MOD-003")
    print("IMPORTANT: Ensure source IP is NOT in known_modbus_masters CDB list")


if __name__ == "__main__":
    main()
