#!/usr/bin/env python3
"""
OT Sentinel — Test: Rapid Modbus Polling / DoS (OT-SENTINEL-MOD-006)

Sends a flood of Modbus requests (mixed FCs) to cross the 200-in-5-minutes
frequency threshold. Triggers Wazuh rule 200008.

Expected Wazuh Alert:
  Rule ID: 200008, Level: 8

Usage:
  python test_rapid_polling.py --target 192.168.56.10 --count 250
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
    parser = argparse.ArgumentParser(description="OT Sentinel Test: MOD-006")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument(
        "--count", type=int, default=250, help="Number of requests (default: 250)"
    )
    args = parser.parse_args()

    source_ip = get_local_ip(args.target, args.port)
    logs = []

    # Mix of function codes to simulate rapid mixed traffic
    function_codes = [1, 2, 3, 4, 1, 3, 3, 4, 2, 1]

    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(args.target, port=args.port, timeout=3)
            if client.connect():
                print(f"Sending {args.count} requests to {args.target}...")
                for i in range(args.count):
                    fc = function_codes[i % len(function_codes)]
                    if fc in (1,):
                        client.read_coils(i % 100, 1)
                    elif fc in (2,):
                        client.read_discrete_inputs(i % 100, 1)
                    elif fc in (3,):
                        client.read_holding_registers(i % 100, 1)
                    elif fc in (4,):
                        client.read_input_registers(i % 100, 1)
                    if i % 50 == 0:
                        print(f"  {i}/{args.count}")
                client.close()
                print("Done.")
            else:
                print("Connection failed — generating log lines only")
        except Exception as e:
            print(f"Error: {e} — generating log lines only")

    for i in range(args.count):
        fc = function_codes[i % len(function_codes)]
        log_entry = {
            "protocol": "modbus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "source_port": 50000 + (i % 1000),
            "destination_ip": args.target,
            "destination_port": args.port,
            "transaction_id": i + 1,
            "unit_id": 1,
            "function_code": fc,
            "function_name": f"fc_{fc:02d}",
            "reference_number": i % 100,
            "count": 1,
            "data": "",
            "event_type": "request",
            "error": None,
        }
        logs.append(json.dumps(log_entry))

    print(f"\nGenerated {len(logs)} log lines")
    print("Sample log line:")
    print(logs[0])
    print("--- Expected Alert ---")
    print("Rule: 200008 | Level: 8 | OT-SENTINEL-MOD-006")
    print(f"Threshold: 200 requests in 5 min → sent {args.count}")


if __name__ == "__main__":
    main()
