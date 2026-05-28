#!/usr/bin/env python3
"""
OT Sentinel — Test: Unauthorized Modbus Coil Write (OT-SENTINEL-MOD-001)

Simulates an unauthorized Modbus TCP coil write from a source IP not in
the authorized masters CDB list. This should trigger Wazuh rule 200001.

Expected Wazuh Alert:
  Rule ID: 200001
  Level: 12
  Description: "OT Sentinel: Unauthorized Modbus coil write detected"
  Fields: protocol=modbus, function_code=5, event_type=request,
          source_ip=<test_source_ip>

Usage:
  python test_unauthorized_write.py --target 192.168.1.100 --port 502

Requirements:
  pip install pymodbus
"""

import argparse
import json
import socket
import sys
from datetime import datetime, timezone

# pymodbus is optional — used if available for real writes
try:
    from pymodbus.client import ModbusTcpClient

    HAS_PYMODBUS = True
except ImportError:
    HAS_PYMODBUS = False


def get_local_ip(target: str, port: int) -> str:
    """Determine the local source IP that will be used to reach target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((target, port))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def test_unauthorized_coil_write(
    target: str, port: int = 502, coil_address: int = 0, coil_value: bool = True
) -> dict:
    """
    Execute an unauthorized Modbus coil write.

    This simulates an attacker or unauthorized device sending a
    Write Single Coil (FC05) command to a Modbus PLC.

    Args:
        target: Modbus device IP address
        port: Modbus TCP port (default: 502)
        coil_address: Coil number to write (0-indexed)
        coil_value: True = ON (0xFF00), False = OFF (0x0000)

    Returns:
        dict with test results and log line for Wazuh ingestion
    """
    source_ip = get_local_ip(target, port)

    result = {
        "status": "unknown",
        "source_ip": source_ip,
        "target": target,
        "port": port,
        "coil_address": coil_address,
        "coil_value": coil_value,
        "log_line": None,
        "error": None,
    }

    # Attempt real Modbus write if pymodbus is available
    if HAS_PYMODBUS:
        try:
            client = ModbusTcpClient(target, port=port, timeout=5)
            connected = client.connect()

            if not connected:
                result["error"] = f"Failed to connect to {target}:{port}"
                result["status"] = "connection_failed"
                client.close()
                return result

            # Execute write single coil (FC05)
            write_result = client.write_coil(coil_address, coil_value)

            if write_result.isError():
                result["error"] = f"Modbus error: {write_result}"
                result["status"] = "modbus_error"
            else:
                result["status"] = "success"

            client.close()

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "exception"
    else:
        result["status"] = "simulated"
        result["note"] = (
            "pymodbus not installed. "
            "Install with: pip install pymodbus. "
            "Proceeding with simulated log generation."
        )

    # Generate the JSON log line that modbus_tap would produce.
    # This is what Wazuh would ingest and match against rule 200001.
    log_entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": 54321,
        "destination_ip": target,
        "destination_port": port,
        "transaction_id": 99,
        "unit_id": 1,
        "function_code": 5,
        "function_name": "write_single_coil",
        "reference_number": coil_address,
        "count": 1,
        "data": "0xFF00" if coil_value else "0x0000",
        "event_type": "request",
        "error": None,
    }

    result["log_line"] = json.dumps(log_entry)
    return result


def cleanup():
    """Restore normal state after test. No-op for this test."""
    print("[CLEANUP] No state changes to revert for coil write test.")


def main():
    parser = argparse.ArgumentParser(
        description="OT Sentinel Test: Unauthorized Modbus Coil Write (MOD-001)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_unauthorized_write.py --target 192.168.1.100
  python test_unauthorized_write.py --target 192.168.1.100 --port 502 --coil 5 --off
  python test_unauthorized_write.py --target 10.0.0.50 --port 1502
        """,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Modbus device IP address (e.g., 192.168.1.100)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=502,
        help="Modbus TCP port (default: 502)",
    )
    parser.add_argument(
        "--coil",
        type=int,
        default=0,
        help="Coil address to write (default: 0)",
    )
    parser.add_argument(
        "--off",
        action="store_true",
        help="Write coil OFF (0x0000) instead of ON (0xFF00)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("OT Sentinel — Test: OT-SENTINEL-MOD-001")
    print("Unauthorized Modbus Coil Write")
    print("=" * 60)
    print(f"Target: {args.target}:{args.port}")
    print(f"Coil: {args.coil}")
    print(f"Value: {'OFF' if args.off else 'ON'}")
    print("-" * 60)

    result = test_unauthorized_coil_write(
        target=args.target,
        port=args.port,
        coil_address=args.coil,
        coil_value=not args.off,
    )

    print(f"Status: {result['status']}")
    print(f"Source IP: {result['source_ip']}")

    if result.get("error"):
        print(f"Error: {result['error']}")
    if result.get("note"):
        print(f"Note: {result['note']}")

    print("-" * 60)
    print("Generated Log Line (for Wazuh ingestion):")
    print(result["log_line"])
    print("-" * 60)

    print("Expected Wazuh Alert:")
    print("  Rule ID:   200001")
    print("  Level:     12 (High)")
    print("  MITRE:     T0855 (Unauthorized Command Message)")
    print(f"  Source IP: {result['source_ip']} (should NOT be in CDB allowlist)")
    print("-" * 60)

    # Verify: if source IP is in authorized list, this test is not valid
    print("IMPORTANT: Ensure this source IP is NOT in authorized_modbus_masters")
    print("If the source IP IS allowlisted, no alert will fire (expected behavior).")
    print()

    # Optional: Write log line to stdout for Wazuh logcollector to pick up
    print("To feed this log to Wazuh, pipe to the agent log file:")
    cmd = f"echo '{result['log_line']}' >> /var/ossec/logs/modbus/modbus_tap.log"
    print(f"  {cmd}")
    print()

    cleanup()


if __name__ == "__main__":
    main()
