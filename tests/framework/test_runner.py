#!/usr/bin/env python3
"""
OT Sentinel — Test Runner

Automated test harness for running all OT Sentinel detection rule tests.
Validates that test scripts execute successfully and produce expected log output.

Usage:
  python test_runner.py --protocol modbus --target 192.168.1.100
  python test_runner.py --all --target 192.168.1.100 --port 502
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional


class TestRunner:
    """Runs OT Sentinel tests and validates results."""

    def __init__(self, repo_root: Path, target: str, port: int = 502):
        self.repo_root = repo_root
        self.target = target
        self.port = port
        self.test_dir = repo_root / "tests"
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def run_test(self, protocol: str, test_name: str) -> bool:
        """Run a single test script."""
        test_path = self.test_dir / protocol / test_name
        if not test_path.exists():
            print(f"  [SKIP] {test_name} — file not found")
            self.skipped += 1
            return False

        print(f"  [RUN]  {test_name}")
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(test_path),
                    "--target",
                    self.target,
                    "--port",
                    str(self.port),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                print(f"  [PASS] {test_name}")
                self.passed += 1
                return True
            else:
                print(f"  [FAIL] {test_name} (exit code {result.returncode})")
                if result.stderr:
                    print(f"    stderr: {result.stderr[:200]}")
                self.failed += 1
                return False

        except subprocess.TimeoutExpired:
            print(f"  [FAIL] {test_name} — timed out after 30s")
            self.failed += 1
            return False
        except Exception as e:
            print(f"  [FAIL] {test_name} — {e}")
            self.failed += 1
            return False

    def run_protocol(self, protocol: str) -> None:
        """Run all tests for a given protocol."""
        protocol_dir = self.test_dir / protocol
        if not protocol_dir.exists():
            print(f"No test directory for protocol: {protocol}")
            return

        test_files = sorted(
            f
            for f in os.listdir(protocol_dir)
            if f.startswith("test_") and f.endswith(".py")
        )

        print(f"\n{'=' * 60}")
        print(f"Protocol: {protocol.upper()} — {len(test_files)} test(s)")
        print(f"{'=' * 60}")

        for test_file in test_files:
            self.run_test(protocol, test_file)

    def run_all(self) -> None:
        """Run tests for all protocols with test directories."""
        protocols = [
            d.name
            for d in self.test_dir.iterdir()
            if d.is_dir() and d.name not in ("framework", "__pycache__")
        ]

        print(f"\n{'#' * 60}")
        print(f"OT Sentinel — Full Test Suite")
        print(f"Target: {self.target}:{self.port}")
        print(f"{'#' * 60}")

        for protocol in sorted(protocols):
            self.run_protocol(protocol)

    def print_summary(self) -> None:
        """Print test summary."""
        total = self.passed + self.failed + self.skipped
        print(f"\n{'=' * 60}")
        print(f"Test Summary: {total} total")
        print(f"  PASSED:  {self.passed}")
        print(f"  FAILED:  {self.failed}")
        print(f"  SKIPPED: {self.skipped}")
        print(f"{'=' * 60}")

        if self.failed > 0:
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="OT Sentinel Test Runner",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target device IP address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=502,
        help="Target port (default: 502)",
    )
    parser.add_argument(
        "--protocol",
        help="Run tests for a specific protocol (modbus, dnp3, iec104, mqtt)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all protocol tests",
    )

    args = parser.parse_args()

    # Determine repo root (2 levels up from tests/framework/)
    repo_root = Path(__file__).resolve().parent.parent.parent

    runner = TestRunner(repo_root, args.target, args.port)

    if args.all:
        runner.run_all()
    elif args.protocol:
        runner.run_protocol(args.protocol)
    else:
        print("Specify --protocol <name> or --all")
        sys.exit(1)

    runner.print_summary()


if __name__ == "__main__":
    main()
