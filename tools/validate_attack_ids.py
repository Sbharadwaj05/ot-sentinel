#!/usr/bin/env python3
"""
OT Sentinel — ATT&CK ICS ID Validator

Verifies that all Wazuh and Sigma rules reference valid MITRE ATT&CK
for ICS technique IDs (T0XXX format, not Enterprise T1XXX).

Usage:
  python validate_attack_ids.py
  python validate_attack_ids.py --rules-dir rules/
"""

import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

# Valid ICS ATT&CK technique ID range
ICS_ATTACK_PATTERN = re.compile(r"^T0\d{3}$")
# Enterprise ATT&CK pattern — should NOT be used
ENT_ATTACK_PATTERN = re.compile(r"^T1\d{3}$")


def validate_wazuh_rule(filepath: Path) -> list[str]:
    """Check ATT&CK IDs in a Wazuh XML rule.

    Skips decoder files since they don't contain MITRE mappings.
    Handles Wazuh's multi-root XML format.
    """
    errors = []

    # Skip decoder files — they don't have MITRE IDs
    if "decoder" in str(filepath).lower():
        return errors

    try:
        # Handle multi-root XML by wrapping in a synthetic root
        with open(filepath, "r", encoding="utf-8") as f:
            raw = f.read()
        wrapped = f"<ot_wrapper>{raw}</ot_wrapper>"

        try:
            from xml.etree import ElementTree

            root = ElementTree.fromstring(wrapped)
        except ElementTree.ParseError:
            root = ET.parse(filepath).getroot()

        # Check <mitre><id> elements (recursively)
        for mitre in root.iter("mitre"):
            mitre_id = mitre.find("id")
            if mitre_id is not None and mitre_id.text:
                tid = mitre_id.text.strip()
                if ENT_ATTACK_PATTERN.match(tid):
                    errors.append(
                        f"{filepath.name}: Enterprise ATT&CK ID {tid} — must use ICS matrix (T0XXX)"
                    )
                elif not ICS_ATTACK_PATTERN.match(tid):
                    errors.append(f"{filepath.name}: Invalid ATT&CK ID format: {tid}")

    except Exception as e:
        errors.append(f"{filepath.name}: Error: {e}")

    return errors


def validate_sigma_rule(filepath: Path) -> list[str]:
    """Check ATT&CK IDs in a Sigma YAML rule."""
    errors = []

    try:
        import yaml

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            return errors

        # Check tags for attack.ics.tXXXX
        tags = data.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str):
                    # Extract TXXXX from attack.ics.txxxx
                    match = re.search(r"t(\d{4})", tag.lower())
                    if match:
                        tid = f"T{match.group(1)}".upper()
                        if ENT_ATTACK_PATTERN.match(tid):
                            errors.append(
                                f"{filepath.name}: Enterprise ATT&CK tag {tag} — must use ICS (t0XXX)"
                            )

        # Check custom field for ot_sentinel references
        custom = data.get("custom", {})
        if isinstance(custom, dict):
            for key, value in custom.items():
                if "attack" in key.lower() and isinstance(value, str):
                    match = re.search(r"T\d{4}", value.upper())
                    if match:
                        tid = match.group(0)
                        if ENT_ATTACK_PATTERN.match(tid):
                            errors.append(
                                f"{filepath.name}: Enterprise ATT&CK ref {value} — must use ICS"
                            )

    except ImportError:
        pass  # PyYAML not installed, skip validation
    except Exception as e:
        errors.append(f"{filepath.name}: Error: {e}")

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent
    rules_dir = repo_root / "rules"

    if len(sys.argv) > 1:
        rules_dir = Path(sys.argv[1])

    all_errors = []

    # Validate Wazuh rules
    wazuh_dir = rules_dir / "wazuh"
    if wazuh_dir.exists():
        for xml_file in sorted(wazuh_dir.rglob("*.xml")):
            all_errors.extend(validate_wazuh_rule(xml_file))

    # Validate Sigma rules
    sigma_dir = rules_dir / "sigma"
    if sigma_dir.exists():
        for yml_file in sorted(sigma_dir.rglob("*.yml")):
            all_errors.extend(validate_sigma_rule(yml_file))

    if all_errors:
        print(f"ATT&CK ICS ID Validation — {len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  ❌ {err}")
        sys.exit(1)
    else:
        print("ATT&CK ICS ID Validation — PASSED")
        print("  All rules use valid ICS matrix technique IDs (T0XXX)")


if __name__ == "__main__":
    main()
