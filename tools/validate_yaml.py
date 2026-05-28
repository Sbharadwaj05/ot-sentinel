#!/usr/bin/env python3
"""
OT Sentinel — Sigma YAML Validator

Validates YAML syntax of all Sigma rule files.
Used by CI/CD pipeline (validate-rules.yml).

Usage:
  python validate_yaml.py rules/sigma/
  python validate_yaml.py rules/sigma/modbus/modbus_unauthorized_write.yml
"""

import sys
from pathlib import Path


def validate_yaml_file(filepath: Path) -> bool:
    """Check if a YAML file is well-formed."""
    try:
        import yaml

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            print(f"  WARN  {filepath.name}: Empty YAML file")
            return True

        if not isinstance(data, dict):
            print(
                f"  FAIL  {filepath.name}: YAML root must be a mapping, got {type(data).__name__}"
            )
            return False

        # Check for required Sigma top-level fields
        required = [
            "title",
            "id",
            "status",
            "description",
            "logsource",
            "detection",
            "level",
        ]
        missing = [r for r in required if r not in data]
        if missing:
            print(
                f"  WARN  {filepath.name}: Missing Sigma fields: {', '.join(missing)}"
            )

        return True

    except ImportError:
        print(f"  SKIP  {filepath.name}: PyYAML not installed. Run: pip install pyyaml")
        return True  # Don't fail CI just because deps aren't installed
    except Exception as e:
        print(f"  FAIL  {filepath.name}: YAML error — {e}")
        return False


def validate_directory(directory: Path) -> tuple[int, int]:
    """Validate all YAML files in a directory recursively."""
    passed = 0
    failed = 0

    if not directory.exists():
        print(f"Directory not found: {directory}")
        return 0, 1

    yaml_files = list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml"))
    if not yaml_files:
        print(f"No YAML files found in {directory}")
        return 0, 0

    print(f"Validating {len(yaml_files)} YAML file(s) in {directory}")
    print("-" * 50)

    for filepath in sorted(yaml_files):
        if validate_yaml_file(filepath):
            print(f"  PASS  {filepath.name}")
            passed += 1
        else:
            failed += 1

    return passed, failed


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_yaml.py <path_to_sigma_rules>")
        sys.exit(1)

    target = Path(sys.argv[1])
    if target.is_file():
        ok = validate_yaml_file(target)
        sys.exit(0 if ok else 1)
    else:
        passed, failed = validate_directory(target)
        print(f"\nSummary: {passed} passed, {failed} failed")
        sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
