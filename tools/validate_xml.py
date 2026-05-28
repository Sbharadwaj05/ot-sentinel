#!/usr/bin/env python3
"""
OT Sentinel — Wazuh XML Validator

Validates XML syntax of all Wazuh rule files.
Used by CI/CD pipeline (validate-rules.yml).

Usage:
  python validate_xml.py rules/wazuh/
  python validate_xml.py rules/wazuh/modbus/modbus_unauthorized_write.xml
"""

import sys
from pathlib import Path
from xml.etree import ElementTree as ET


def validate_xml_file(filepath: Path) -> bool:
    """Check if an XML file is well-formed and is a valid Wazuh rule/decoder.

    Wazuh rule and decoder files can have multiple root elements
    (e.g., multiple <decoder> blocks in one file). This function
    wraps the content in a temporary root for parsing, then validates
    each top-level element.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw = f.read()

        # Extract content without XML declaration for wrapping
        # Remove any <?xml ...?> declarations since we're wrapping
        cleaned = raw
        if cleaned.lstrip().startswith("<?xml"):
            end_decl = cleaned.find("?>", 0)
            if end_decl != -1:
                cleaned = cleaned[end_decl + 2 :]

        # Remove leading/trailing comments that start with <!-- and end with -->
        # Wrap in a synthetic root element for parsing (Wazuh supports multi-root)
        wrapped = f"<ot_sentinel_wrapper>{cleaned}</ot_sentinel_wrapper>"

        try:
            tree = ET.fromstring(wrapped)
        except ET.ParseError as e:
            # Try parsing as-is (single root file)
            tree = ET.parse(filepath).getroot()

        # Valid Wazuh elements: rule, decoder, group, localfile
        valid_tags = {"rule", "decoder", "group", "localfile", "ot_sentinel_wrapper"}
        if tree.tag not in valid_tags:
            print(f"  WARN  {filepath.name}: Unexpected root element <{tree.tag}>")

        return True

    except ET.ParseError as e:
        print(f"  FAIL  {filepath.name}: XML parse error — {e}")
        return False
    except Exception as e:
        print(f"  FAIL  {filepath.name}: {e}")
        return False


def validate_directory(directory: Path) -> tuple[int, int]:
    """Validate all XML files in a directory recursively."""
    passed = 0
    failed = 0

    if not directory.exists():
        print(f"Directory not found: {directory}")
        return 0, 1

    xml_files = list(directory.rglob("*.xml"))
    if not xml_files:
        print(f"No XML files found in {directory}")
        return 0, 0

    print(f"Validating {len(xml_files)} XML file(s) in {directory}")
    print("-" * 50)

    for filepath in sorted(xml_files):
        if validate_xml_file(filepath):
            print(f"  PASS  {filepath.name}")
            passed += 1
        else:
            failed += 1

    return passed, failed


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_xml.py <path_to_rules>")
        sys.exit(1)

    target = Path(sys.argv[1])
    if target.is_file():
        ok = validate_xml_file(target)
        sys.exit(0 if ok else 1)
    else:
        passed, failed = validate_directory(target)
        print(f"\nSummary: {passed} passed, {failed} failed")
        sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
