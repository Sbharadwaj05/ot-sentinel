#!/usr/bin/env python3
"""
OT Sentinel — Test: Modbus Exception Response Flood (OT-SENTINEL-MOD-007)

Sends reads to invalid/nonexistent register ranges to trigger exception
responses from the PLC. Triggers Wazuh rule 200010 when 30+ exceptions
occur in 5 minutes.

Expected Wazuh Alert:
  Rule ID: 200010, Level: 7

Usage:
  python test_exception_flood.py --target 192.168.56.10 --count 40
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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-007")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument(
        "--count", type=int, default=40, help="Number of probes (default: 40)"
    )
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)
    logs = []

    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(args.target, port=args.port, timeout=3)
            if client.connect():
                print(f"Probing {args.count} invalid register addresses...")
                for i in range(args.count):
                    # Read from very high register addresses that won't exist
                    client.read_holding_registers(50000 + i * 100, 10)
                    if i % 10 == 0:
                        print(f"  {i}/{args.count}")
                client.close()
                print("Done — PLC should have returned exception responses.")
            else:
                print("Connection failed — generating log lines only")
        except Exception as e:
            print(f"Error: {e} — generating log lines only")

    # Generate exception response log lines (FC 128+ = exception responses)
    for i in range(args.count):
        log_entry = {
            "protocol": "modbus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": args.target,  # Exception comes FROM the PLC
            "source_port": args.port,
            "destination_ip": source_ip,  # TO the requesting client
            "destination_port": 50000 + i,
            "transaction_id": i + 1,
            "unit_id": 1,
            "function_code": 131,  # FC 0x83 = read holding registers exception
            "function_name": "exception_response",
            "reference_number": 50000 + i * 100,
            "count": 0,
            "data": "0x02",  # Exception code 2 = illegal data address
            "event_type": "response",
            "error": "illegal_data_address",
        }
        logs.append(json.dumps(log_entry))

    print(f"\nGenerated {len(logs)} exception response log lines")
    print("Sample:")
    print(logs[0])
    print("--- Expected Alert ---")
    print("Rule: 200010 | Level: 7 | OT-SENTINEL-MOD-007")
    print(f"Threshold: 30 exceptions in 5 min → sent {args.count}")


if __name__ == "__main__":
    main()
