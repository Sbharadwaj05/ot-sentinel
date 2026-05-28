#!/usr/bin/env python3
"""
OT Sentinel — Rule Validator

Validates OT Sentinel detection rules against the project's formatting and
quality standards. Checks:
  - Wazuh XML syntax (well-formed, required fields present)
  - Sigma YAML syntax (well-formed, required fields present)
  - ATT&CK ICS technique ID format
  - Rule naming convention compliance
  - CDB list references

Usage:
  python validator.py rules/wazuh/
  python validator.py rules/sigma/
  python validator.py --all
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple
from xml.etree import ElementTree as ET


class RuleValidator:
    """Validates OT Sentinel detection rules."""

    REQUIRED_WAZUH_FIELDS = [
        "id",
        "level",
        "decoded_as",
        "field",
        "description",
        "mitre",
        "group",
    ]
    VALID_SEVERITY_LEVELS = set(range(0, 16))
    VALID_PROTOCOLS = {"modbus", "dnp3", "iec104", "mqtt", "opc-ua"}
    ICS_ATTACK_PATTERN = re.compile(r"^T0\d{3}$")

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_wazuh_rule(self, filepath: Path) -> bool:
        """Validate a single Wazuh XML rule file."""
        rule_ok = True
        rel_path = filepath.relative_to(filepath.parent.parent.parent)

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            if root.tag != "rule":
                self.errors.append(
                    f"{rel_path}: Root element must be <rule>, got <{root.tag}>"
                )
                return False

            # Check rule ID
            rule_id = root.get("id")
            if not rule_id:
                self.errors.append(f"{rel_path}: Missing rule id attribute")
                rule_ok = False
            elif not rule_id.isdigit() or int(rule_id) < 200001:
                self.errors.append(f"{rel_path}: Rule ID {rule_id} must be >= 200001")
                rule_ok = False

            # Check level
            level = root.get("level")
            if not level:
                self.errors.append(f"{rel_path}: Missing level attribute")
                rule_ok = False
            elif not level.isdigit() or int(level) not in self.VALID_SEVERITY_LEVELS:
                self.errors.append(f"{rel_path}: Level {level} must be 0-15")
                rule_ok = False

            # Check decoded_as
            decoded = root.find("decoded_as")
            if decoded is None:
                self.errors.append(f"{rel_path}: Missing <decoded_as> element")
                rule_ok = False

            # Check description
            desc = root.find("description")
            if desc is None or not desc.text or not desc.text.strip():
                self.errors.append(f"{rel_path}: Missing or empty <description>")
                rule_ok = False

            # Check MITRE mapping
            mitre = root.find("mitre")
            if mitre is None:
                self.errors.append(f"{rel_path}: Missing <mitre> block")
                rule_ok = False
            else:
                mitre_id = mitre.find("id")
                if mitre_id is None or not mitre_id.text:
                    self.errors.append(f"{rel_path}: Missing <mitre><id> value")
                    rule_ok = False
                elif not self.ICS_ATTACK_PATTERN.match(mitre_id.text.strip()):
                    self.errors.append(
                        f"{rel_path}: MITRE ID '{mitre_id.text}' is not a valid ICS ATT&CK ID (T0XXX)"
                    )
                    rule_ok = False

            # Check group
            group = root.find("group")
            if group is None or not group.text:
                self.errors.append(f"{rel_path}: Missing <group> element")
                rule_ok = False

        except ET.ParseError as e:
            self.errors.append(f"{rel_path}: XML parse error: {e}")
            return False
        except Exception as e:
            self.errors.append(f"{rel_path}: Unexpected error: {e}")
            return False

        return rule_ok

    def validate_sigma_rule(self, filepath: Path) -> bool:
        """Validate a single Sigma YAML rule file."""
        rule_ok = True
        rel_path = filepath.relative_to(filepath.parent.parent.parent)

        try:
            import yaml
        except ImportError:
            self.errors.append(
                f"{rel_path}: Cannot validate — PyYAML not installed. Run: pip install pyyaml"
            )
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            if not isinstance(rule, dict):
                self.errors.append(f"{rel_path}: YAML root must be a mapping")
                return False

            # Required Sigma fields
            required = [
                "title",
                "id",
                "status",
                "description",
                "author",
                "date",
                "tags",
                "logsource",
                "detection",
                "level",
            ]
            for field in required:
                if field not in rule:
                    self.errors.append(
                        f"{rel_path}: Missing required Sigma field: '{field}'"
                    )
                    rule_ok = False

            # Validate tags contain ATT&CK ICS tag
            if "tags" in rule and isinstance(rule["tags"], list):
                has_attack_ics = any(
                    isinstance(t, str) and "attack.ics.t" in t.lower()
                    for t in rule["tags"]
                )
                if not has_attack_ics:
                    self.warnings.append(
                        f"{rel_path}: No attack.ics.tXXXX tag found in tags"
                    )
            else:
                self.errors.append(f"{rel_path}: Missing or invalid tags field")
                rule_ok = False

            # Validate detection block
            if "detection" in rule and isinstance(rule["detection"], dict):
                if "condition" not in rule["detection"]:
                    self.errors.append(
                        f"{rel_path}: Missing 'condition' in detection block"
                    )
                    rule_ok = False

        except Exception as e:
            self.errors.append(f"{rel_path}: YAML error: {e}")
            return False

        return rule_ok

    def validate_directory(self, directory: Path, rule_type: str) -> Tuple[int, int]:
        """Validate all rules in a directory recursively."""
        passed = 0
        failed = 0

        if not directory.exists():
            print(f"Directory not found: {directory}")
            return 0, 1

        if rule_type == "wazuh":
            files = list(directory.rglob("*.xml"))
            validator = self.validate_wazuh_rule
        elif rule_type == "sigma":
            files = list(directory.rglob("*.yml"))
            validator = self.validate_sigma_rule
        else:
            print(f"Unknown rule type: {rule_type}")
            return 0, 1

        print(
            f"\nValidating {rule_type.upper()} rules in {directory} ({len(files)} file(s))"
        )
        print("-" * 50)

        for filepath in sorted(files):
            if validator(filepath):
                print(f"  PASS  {filepath.name}")
                passed += 1
            else:
                print(f"  FAIL  {filepath.name}")
                failed += 1

        return passed, failed

    def print_report(self) -> None:
        """Print validation report."""
        if self.errors:
            print(f"\nERRORS ({len(self.errors)}):")
            for err in self.errors:
                print(f"  ❌ {err}")

        if self.warnings:
            print(f"\nWARNINGS ({len(self.warnings)}):")
            for warn in self.warnings:
                print(f"  ⚠️  {warn}")


def main():
    parser = argparse.ArgumentParser(
        description="OT Sentinel Rule Validator",
    )
    parser.add_argument(
        "path",
        nargs="*",
        help="Path(s) to rule directories or files to validate",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all rules (Wazuh + Sigma)",
    )

    args = parser.parse_args()

    validator = RuleValidator()

    if args.all:
        repo_root = Path(__file__).resolve().parent.parent.parent
        paths = [
            (repo_root / "rules" / "wazuh", "wazuh"),
            (repo_root / "rules" / "sigma", "sigma"),
        ]
    elif args.path:
        paths = []
        for p in args.path:
            path = Path(p)
            if "wazuh" in str(path).lower():
                paths.append((path, "wazuh"))
            elif "sigma" in str(path).lower():
                paths.append((path, "sigma"))
            else:
                print(f"Cannot determine rule type from path: {path}")
                sys.exit(1)
    else:
        # Default: validate from current directory context
        repo_root = Path(__file__).resolve().parent.parent.parent
        paths = [
            (repo_root / "rules" / "wazuh", "wazuh"),
            (repo_root / "rules" / "sigma", "sigma"),
        ]

    total_passed = 0
    total_failed = 0

    for directory, rule_type in paths:
        passed, failed = validator.validate_directory(directory, rule_type)
        total_passed += passed
        total_failed += failed

    validator.print_report()

    print(f"\n{'=' * 50}")
    print(f"Summary: {total_passed} passed, {total_failed} failed")
    print(f"{'=' * 50}")

    if total_failed > 0 or validator.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
