#!/usr/bin/env python3
"""
OT Sentinel — Rule Naming Convention Checker

Verifies that all rule files follow the OT Sentinel naming convention
and that rule IDs are sequential without gaps.

Usage:
  python check_naming.py
  python check_naming.py --rules-dir rules/
"""

import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

# Expected rule ID pattern
RULE_ID_PATTERN = re.compile(
    r"^OT-SENTINEL-(MOD|DNP|IEC|MQT{1,2}|OPC|EIP|BAC|PRO)-\d{3}$"
)

# Wazuh rule ID starting point
WAZUH_ID_START = 200001

# Protocol directories and their expected prefixes
PROTOCOL_PREFIXES = {
    "modbus": "MOD",
    "dnp3": "DNP",
    "iec104": "IEC",
    "mqtt": "MQT",
    "opc-ua": "OPC",
}


def extract_rule_id_from_xml(filepath: Path) -> str | None:
    """Extract OT-SENTINEL-XXX-NNN from comment header or rule id attribute."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Try to find in XML comment header first
        match = re.search(r"Rule:\s*(OT-SENTINEL-\w+-\d+)", content)
        if match:
            return match.group(1)

        # Fallback: parse XML and check rule id attribute
        tree = ET.fromstring(content)
        rule_id = tree.get("id")
        if rule_id:
            return f"Wazuh-ID-{rule_id}"

    except Exception:
        pass

    return None


def extract_rule_id_from_sigma(filepath: Path) -> str | None:
    """Extract OT-SENTINEL-XXX-NNN from Sigma YAML rule."""
    try:
        import yaml

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if isinstance(data, dict):
            # Check custom metadata
            custom = data.get("custom", {})
            if isinstance(custom, dict) and "ot_sentinel_rule_id" in custom:
                return custom["ot_sentinel_rule_id"]

            # Check id field for pattern
            rule_id = data.get("id", "")
            if isinstance(rule_id, str) and "ot-sentinel" in rule_id.lower():
                parts = rule_id.upper().replace("-", " ").split()
                # Try to reconstruct: OT-SENTINEL-MOD-001
                if len(parts) >= 3:
                    return f"OT-SENTINEL-{parts[-2]}-{parts[-1]}"

    except ImportError:
        pass
    except Exception:
        pass

    return None


def check_naming(directory: Path) -> list[str]:
    """Check rule naming conventions in a directory."""
    errors = []
    rule_ids_found = {}

    # Check Wazuh rules
    wazuh_dir = directory / "wazuh"
    if wazuh_dir.exists():
        for xml_file in sorted(wazuh_dir.rglob("*.xml")):
            # Skip decoders and non-rule files
            if "decoder" in str(xml_file).lower() or "local_rules" in str(xml_file):
                continue

            rule_id = extract_rule_id_from_xml(xml_file)
            if rule_id and RULE_ID_PATTERN.match(rule_id):
                protocol = rule_id.split("-")[2]
                number = int(rule_id.split("-")[3])
                if protocol not in rule_ids_found:
                    rule_ids_found[protocol] = []
                rule_ids_found[protocol].append((number, xml_file.name))
            elif rule_id:
                print(
                    f"  WARN  {xml_file.name}: Rule ID '{rule_id}' doesn't match convention"
                )
            else:
                print(f"  WARN  {xml_file.name}: Could not extract rule ID")

    # Check Sigma rules
    sigma_dir = directory / "sigma"
    if sigma_dir.exists():
        for yml_file in sorted(sigma_dir.rglob("*.yml")):
            rule_id = extract_rule_id_from_sigma(yml_file)
            if rule_id and RULE_ID_PATTERN.match(rule_id):
                protocol = rule_id.split("-")[2]
                number = int(rule_id.split("-")[3])
                if protocol not in rule_ids_found:
                    rule_ids_found[protocol] = []
                rule_ids_found[protocol].append((number, f"{yml_file.name} (sigma)"))
            elif rule_id:
                print(
                    f"  WARN  {yml_file.name}: Rule ID '{rule_id}' doesn't match convention"
                )

    # Check for gaps in numbering
    # Note: Wazuh XML and Sigma YAML rules share the same OT-SENTINEL-XXX-NNN ID,
    # so duplicates across file types are expected (one XML + one YAML per rule).
    # We only flag duplicates within the same file type.
    for protocol, ids in rule_ids_found.items():
        ids.sort()
        numbers = [n for n, _ in ids]
        expected = list(range(1, max(numbers) + 1))
        gaps = set(expected) - set(numbers)

        # Check for duplicates within the same file type only
        xml_numbers = [n for n, f in ids if not f.endswith("(sigma)")]
        sigma_numbers = [n for n, f in ids if f.endswith("(sigma)")]

        xml_dupes = [n for n in xml_numbers if xml_numbers.count(n) > 1]
        sigma_dupes = [n for n in sigma_numbers if sigma_numbers.count(n) > 1]

        if gaps:
            errors.append(f"Protocol {protocol}: Missing rule numbers: {sorted(gaps)}")
        if xml_dupes:
            errors.append(
                f"Protocol {protocol}: Duplicate Wazuh rule numbers: {sorted(set(xml_dupes))}"
            )
        if sigma_dupes:
            errors.append(
                f"Protocol {protocol}: Duplicate Sigma rule numbers: {sorted(set(sigma_dupes))}"
            )

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent
    rules_dir = repo_root / "rules"

    if len(sys.argv) > 1 and sys.argv[1] != "--rules-dir":
        rules_dir = Path(sys.argv[1])
    elif len(sys.argv) > 2:
        rules_dir = Path(sys.argv[2])

    print("OT Sentinel Rule Naming Convention Check")
    print("-" * 50)

    errors = check_naming(rules_dir)

    if errors:
        print(f"\nNaming convention VIOLATIONS ({len(errors)}):")
        for err in errors:
            print(f"  ❌ {err}")
        sys.exit(1)
    else:
        print("\n✅ All rule files follow the naming convention.")
        print("✅ Rule numbering is sequential with no gaps.")


if __name__ == "__main__":
    main()
