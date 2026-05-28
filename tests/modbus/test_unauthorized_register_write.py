#!/usr/bin/env python3
"""
OT Sentinel — Test: Unauthorized Modbus Register Write (OT-SENTINEL-MOD-002)

Simulates an unauthorized Modbus holding register write (FC06) from a source
IP not in the authorized masters CDB list. Should trigger Wazuh rule 200002.

Expected Wazuh Alert:
  Rule ID: 200002, Level: 12
  Description: "OT Sentinel: Unauthorized Modbus register write detected"

Usage:
  python test_unauthorized_register_write.py --target 192.168.56.10 --port 502
"""

import argparse
import json
import socket
import sys
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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-002")
    parser.add_argument("--target", required=True, help="Modbus device IP")
    parser.add_argument("--port", type=int, default=502, help="Modbus port")
    parser.add_argument("--register", type=int, default=100, help="Register address")
    parser.add_argument("--value", type=int, default=3000, help="Value to write")
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)
    status = "simulated"

    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(args.target, port=args.port, timeout=5)
            if client.connect():
                result = client.write_register(args.register, args.value)
                status = "success" if not result.isError() else "modbus_error"
            else:
                status = "connection_failed"
            client.close()
        except Exception as e:
            status = f"exception: {e}"
    else:
        status = "simulated (pymodbus not installed)"

    log_entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": 54321,
        "destination_ip": args.target,
        "destination_port": args.port,
        "transaction_id": 99,
        "unit_id": 1,
        "function_code": 6,
        "function_name": "write_single_register",
        "reference_number": args.register,
        "count": 1,
        "data": f"0x{args.value:04X}",
        "event_type": "request",
        "error": None,
    }

    print(f"Status: {status}")
    print(f"Source IP: {source_ip}")
    print("--- Generated Log for Wazuh ---")
    print(json.dumps(log_entry))
    print("--- Expected Alert ---")
    print("Rule: 200002 | Level: 12 | OT-SENTINEL-MOD-002")
    print("IMPORTANT: Ensure this source IP is NOT in authorized_modbus_masters")


if __name__ == "__main__":
    main()
