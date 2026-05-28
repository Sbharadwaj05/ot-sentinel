#!/usr/bin/env python3
"""
OT Sentinel — Modbus Traffic Monitor (modbus_tap.py)

Monitors Modbus TCP traffic and outputs JSON log lines for Wazuh ingestion.
Can capture live traffic via scapy, read from pcap files, accept JSON from
stdin, or generate demo traffic for testing.

Output format (one JSON object per line):
  {"protocol":"modbus","timestamp":"...","source_ip":"...","source_port":...,
   "destination_ip":"...","destination_port":502,"transaction_id":1,
   "unit_id":1,"function_code":5,"function_name":"write_single_coil",
   "reference_number":0,"count":1,"data":"0xFF00","event_type":"request"}

Usage:
  python modbus_tap.py --interface eth0                    # Live capture
  python modbus_tap.py --pcap capture.pcapng               # PCAP replay
  python modbus_tap.py --demo --target 192.168.1.100       # Generate test traffic
  python modbus_tap.py --stdin                              # Read JSON from stdin
  tail -f modbus_tap.log | python modbus_tap.py --stdin    # Forward to Wazuh

Installation:
  pip install pymodbus          # Required for --demo mode
  pip install scapy             # Required for live capture / pcap reading
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Optional

# Try importing optional dependencies
try:
    from scapy.all import IP, TCP, Raw, rdpcap, sniff
    from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from pymodbus.client import ModbusTcpClient

    HAS_PYMODBUS = True
except ImportError:
    HAS_PYMODBUS = False


# Modbus function code to name mapping
FC_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    7: "read_exception_status",
    8: "diagnostics",
    11: "get_comm_event_counter",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    17: "report_server_id",
    20: "read_file_record",
    21: "write_file_record",
    22: "mask_write_register",
    23: "read_write_multiple_registers",
    24: "read_fifo_queue",
    43: "encapsulated_interface_transport",
}


def make_log_entry(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    transaction_id: int,
    unit_id: int,
    function_code: int,
    reference_number: int = 0,
    count: int = 1,
    data: str = "",
    event_type: str = "request",
) -> str:
    """Create a JSON log entry in the format expected by modbus_decoder.xml."""
    entry = {
        "protocol": "modbus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "function_name": FC_NAMES.get(function_code, f"unknown_{function_code}"),
        "reference_number": reference_number,
        "count": count,
        "data": data,
        "event_type": event_type,
        "error": None,
    }
    return json.dumps(entry)


def run_live_capture(interface: str, port_filter: int = 502) -> None:
    """Capture Modbus TCP traffic on a network interface."""
    if not HAS_SCAPY:
        print(
            "ERROR: scapy is required for live capture. Install: pip install scapy",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"[modbus_tap] Capturing Modbus TCP on interface {interface}, port {port_filter}",
        file=sys.stderr,
    )

    def process_packet(pkt):
        """Process each captured packet and output JSON log line."""
        if not (IP in pkt and TCP in pkt):
            return
        if pkt[TCP].dport != port_filter and pkt[TCP].sport != port_filter:
            return

        # Determine if this is a request (to port 502) or response (from port 502)
        is_request = pkt[TCP].dport == port_filter

        try:
            if Raw in pkt:
                payload = bytes(pkt[Raw])
                if len(payload) < 8:
                    return  # Too short to be valid Modbus TCP

                # Parse Modbus TCP header (MBAP)
                transaction_id = int.from_bytes(payload[0:2], "big")
                # protocol_id = int.from_bytes(payload[2:4], "big")  # Always 0x0000
                # length = int.from_bytes(payload[4:6], "big")
                unit_id = payload[6]
                function_code = payload[7]

                # Extract data portion (bytes after MBAP header + FC)
                data_bytes = payload[8:]
                data_hex = data_bytes.hex() if data_bytes else ""

                log_line = make_log_entry(
                    source_ip=pkt[IP].src,
                    source_port=pkt[TCP].sport,
                    destination_ip=pkt[IP].dst,
                    destination_port=pkt[TCP].dport,
                    transaction_id=transaction_id,
                    unit_id=unit_id,
                    function_code=function_code,
                    data=data_hex if data_hex else "",
                    event_type="request" if is_request else "response",
                )
                print(log_line, flush=True)

        except Exception as e:
            print(f"[modbus_tap] Error parsing packet: {e}", file=sys.stderr)

    sniff(
        iface=interface, filter=f"tcp port {port_filter}", prn=process_packet, store=0
    )


def run_pcap_replay(pcap_path: str, port_filter: int = 502) -> None:
    """Replay Modbus traffic from a pcap file."""
    if not HAS_SCAPY:
        print(
            "ERROR: scapy is required for PCAP replay. Install: pip install scapy",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"[modbus_tap] Replaying Modbus TCP from {pcap_path}, port {port_filter}",
        file=sys.stderr,
    )

    packets = rdpcap(pcap_path)
    for pkt in packets:
        if not (IP in pkt and TCP in pkt):
            continue
        if pkt[TCP].dport != port_filter and pkt[TCP].sport != port_filter:
            continue

        is_request = pkt[TCP].dport == port_filter

        try:
            if Raw in pkt:
                payload = bytes(pkt[Raw])
                if len(payload) < 8:
                    continue

                transaction_id = int.from_bytes(payload[0:2], "big")
                unit_id = payload[6]
                function_code = payload[7]
                data_bytes = payload[8:]
                data_hex = data_bytes.hex() if data_bytes else ""

                log_line = make_log_entry(
                    source_ip=pkt[IP].src,
                    source_port=pkt[TCP].sport,
                    destination_ip=pkt[IP].dst,
                    destination_port=pkt[TCP].dport,
                    transaction_id=transaction_id,
                    unit_id=unit_id,
                    function_code=function_code,
                    data=data_hex if data_hex else "",
                    event_type="request" if is_request else "response",
                )
                print(log_line, flush=True)

        except Exception as e:
            print(f"[modbus_tap] Error parsing packet: {e}", file=sys.stderr)


def run_demo(target: str, port: int = 502) -> None:
    """Generate demo Modbus traffic for testing OT Sentinel rules.

    Simulates a legitimate SCADA read cycle and an unauthorized write.
    """
    if not HAS_PYMODBUS:
        print(
            "ERROR: pymodbus is required for demo mode. Install: pip install pymodbus",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"[modbus_tap] Demo mode — generating test traffic to {target}:{port}",
        file=sys.stderr,
    )

    # Simulate a SCADA server doing normal reads
    scada_ip = "192.168.1.10"
    print(f"[modbus_tap] Simulating SCADA reads from {scada_ip}...", file=sys.stderr)

    for i in range(3):
        log_line = make_log_entry(
            source_ip=scada_ip,
            source_port=40000 + i,
            destination_ip=target,
            destination_port=port,
            transaction_id=i + 1,
            unit_id=1,
            function_code=3,  # Read Holding Registers
            reference_number=0,
            count=10,
            data="",
            event_type="request",
        )
        print(log_line, flush=True)

    # Simulate an unauthorized coil write
    attacker_ip = "192.168.1.200"
    print(
        f"[modbus_tap] Simulating UNAUTHORIZED coil write from {attacker_ip}...",
        file=sys.stderr,
    )
    print(
        f"[modbus_tap] >>> This should trigger Wazuh rule 200001 (OT-SENTINEL-MOD-001)",
        file=sys.stderr,
    )

    log_line = make_log_entry(
        source_ip=attacker_ip,
        source_port=55555,
        destination_ip=target,
        destination_port=port,
        transaction_id=99,
        unit_id=1,
        function_code=5,  # Write Single Coil
        reference_number=0,
        count=1,
        data="0xFF00",
        event_type="request",
    )
    print(log_line, flush=True)

    # Simulate an unauthorized register write
    print(
        f"[modbus_tap] Simulating UNAUTHORIZED register write from {attacker_ip}...",
        file=sys.stderr,
    )
    print(
        f"[modbus_tap] >>> This should trigger Wazuh rule 200003 (OT-SENTINEL-MOD-002)",
        file=sys.stderr,
    )

    log_line = make_log_entry(
        source_ip=attacker_ip,
        source_port=55556,
        destination_ip=target,
        destination_port=port,
        transaction_id=100,
        unit_id=1,
        function_code=6,  # Write Single Register
        reference_number=100,
        count=1,
        data="0x0BB8",
        event_type="request",
    )
    print(log_line, flush=True)

    print(f"[modbus_tap] Demo complete — generated 5 log lines", file=sys.stderr)


def run_stdin() -> None:
    """Pass JSON from stdin to stdout (passthrough mode for log forwarding)."""
    print(
        "[modbus_tap] Stdin passthrough mode — forwarding JSON lines", file=sys.stderr
    )
    for line in sys.stdin:
        line = line.strip()
        if line:
            try:
                # Validate it's valid JSON
                json.loads(line)
                print(line, flush=True)
            except json.JSONDecodeError:
                # Not JSON — try to wrap it or skip
                pass


def main():
    parser = argparse.ArgumentParser(
        description="OT Sentinel — Modbus Traffic Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python modbus_tap.py --interface eth0                    # Live capture
  python modbus_tap.py --pcap capture.pcapng               # PCAP replay
  python modbus_tap.py --demo --target 192.168.1.100       # Generate test traffic
  python modbus_tap.py --stdin                              # JSON passthrough
  tail -f modbus_tap.log | python modbus_tap.py --stdin    # Forward to Wazuh
        """,
    )
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--pcap", help="PCAP file to replay")
    parser.add_argument(
        "--demo", action="store_true", help="Generate demo Modbus traffic"
    )
    parser.add_argument("--target", help="Target Modbus device IP (for demo mode)")
    parser.add_argument(
        "--port", type=int, default=502, help="Modbus port (default: 502)"
    )
    parser.add_argument(
        "--stdin", action="store_true", help="Passthrough JSON from stdin"
    )

    args = parser.parse_args()

    if args.stdin:
        run_stdin()
    elif args.demo:
        if not args.target:
            print("ERROR: --target is required for --demo mode", file=sys.stderr)
            sys.exit(1)
        run_demo(args.target, args.port)
    elif args.pcap:
        run_pcap_replay(args.pcap, args.port)
    elif args.interface:
        run_live_capture(args.interface, args.port)
    else:
        parser.print_help()
        print(
            "\nNo mode selected. Choose --interface, --pcap, --demo, or --stdin",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
