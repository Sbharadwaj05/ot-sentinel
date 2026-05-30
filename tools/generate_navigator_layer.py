#!/usr/bin/env python3
"""
OT Sentinel — ATT&CK Navigator Layer Generator

Generates a MITRE ATT&CK Navigator layer JSON file showing OT Sentinel's
current detection coverage against the ICS matrix.

Usage:
  python generate_navigator_layer.py
  python generate_navigator_layer.py --output mappings/coverage_heatmap.json
"""

import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

# Complete MITRE ATT&CK for ICS techniques (as of v16)
# Used to build the background layer showing all possible techniques
ICS_TECHNIQUES = {
    "Initial Access": [
        "T0817",
        "T0861",
        "T0862",
        "T0886",
    ],
    "Execution": [
        "T0803",
        "T0805",
        "T0806",
        "T0855",
        "T0869",
        "T0870",
        "T0871",
    ],
    "Persistence": [
        "T0833",
        "T0838",
        "T0857",
        "T0877",
        "T0891",
        "T0893",
        "T0894",
    ],
    "Privilege Escalation": [
        "T0890",
        "T0891",
    ],
    "Evasion": [
        "T0821",
        "T0834",
        "T0858",
        "T0873",
        "T0892",
    ],
    "Discovery": [
        "T0840",
        "T0842",
        "T0846",
        "T0882",
        "T0884",
        "T0888",
    ],
    "Lateral Movement": [
        "T0808",
        "T0812",
        "T0843",
        "T0866",
        "T0895",
    ],
    "Collection": [
        "T0802",
        "T0852",
        "T0881",
    ],
    "Command and Control": [
        "T0801",
        "T0856",
        "T0869",
        "T0885",
    ],
    "Inhibit Response Function": [
        "T0804",
        "T0807",
        "T0816",
        "T0820",
        "T0859",
        "T0876",
        "T0878",
        "T0879",
    ],
    "Impair Process Control": [
        "T0800",
        "T0809",
        "T0810",
        "T0813",
        "T0814",
        "T0820",
        "T0831",
        "T0832",
        "T0836",
        "T0837",
        "T0855",
        "T0859",
        "T0867",
        "T0868",
    ],
    "Impact": [
        "T0815",
        "T0817",
        "T0826",
        "T0827",
        "T0828",
        "T0829",
        "T0883",
        "T0889",
    ],
}

# Color scheme for coverage levels
COLORS = {
    "covered": "#4caf50",  # Green — rule exists and tested
    "experimental": "#ff9800",  # Orange — rule exists, not yet tested
    "planned": "#2196f3",  # Blue — rule planned, not yet implemented
    "uncovered": "#f5f5f5",  # Light grey — no coverage
}


def extract_mitre_ids_from_rules(rules_dir: Path) -> dict[str, str]:
    """Scan all rules and extract MITRE ATT&CK ICS technique IDs with status."""
    coverage = {}

    # Scan Wazuh rules
    wazuh_dir = rules_dir / "wazuh"
    if wazuh_dir.exists():
        for xml_file in wazuh_dir.rglob("*.xml"):
            if "decoder" in str(xml_file).lower():
                continue
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                # Fixed: use iter() for nested <mitre> inside <rule> inside <group>
                mitre_elems = list(root.iter("mitre"))
                mitre = mitre_elems[0] if mitre_elems else None
                if mitre is not None:
                    mitre_id = mitre.find("id")
                    if mitre_id is not None and mitre_id.text:
                        tid = mitre_id.text.strip()
                        # Status from rule comment or attribute
                        status = "experimental"
                        coverage[tid] = status
            except Exception:
                pass

    # Scan Sigma rules
    sigma_dir = rules_dir / "sigma"
    if sigma_dir.exists():
        try:
            import yaml

            for yml_file in sigma_dir.rglob("*.yml"):
                try:
                    with open(yml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        tags = data.get("tags", [])
                        for tag in tags:
                            if isinstance(tag, str) and "attack.ics.t" in tag.lower():
                                match = re.search(r"t(\d{4})", tag.lower())
                                if match:
                                    tid = f"T{match.group(1)}".upper()
                                    status = data.get("status", "experimental")
                                    coverage[tid] = status
                except Exception:
                    pass
        except ImportError:
            pass

    return coverage


def generate_navigator_layer(coverage: dict[str, str], output_path: Path) -> None:
    """Generate ATT&CK Navigator layer JSON."""

    techniques = []

    for tactic, tech_ids in ICS_TECHNIQUES.items():
        for tid in tech_ids:
            entry = {
                "techniqueID": tid,
                "tactic": tactic.lower().replace(" ", "-"),
            }

            if tid in coverage:
                status = coverage[tid]
                if status in ("tested", "stable"):
                    entry["color"] = COLORS["covered"]
                    entry["comment"] = "Covered — rule tested in lab"
                    entry["enabled"] = True
                elif status == "experimental":
                    entry["color"] = COLORS["experimental"]
                    entry["comment"] = "Covered — experimental (pending lab test)"
                    entry["enabled"] = True
            else:
                entry["color"] = COLORS["uncovered"]
                entry["comment"] = "No detection coverage yet"
                entry["enabled"] = True

            techniques.append(entry)

    layer = {
        "name": "OT Sentinel — ATT&CK for ICS Coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "ics-attack",
        "description": (
            "OT Sentinel detection rule coverage mapped to MITRE ATT&CK for ICS. "
            f"Green = tested rules, Orange = experimental rules. "
            f"Generated: 2026-05-27. "
            f"Rules loaded: {len(coverage)} technique(s) covered."
        ),
        "filters": {
            "platforms": [
                "Field Controller/RTU/PLC/IED",
                "Human-Machine Interface",
                "Engineering Workstation",
                "SCADA Server",
                "Data Historian",
            ],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubdomains": "operating-systems",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [
                COLORS["uncovered"],
                COLORS["experimental"],
                COLORS["covered"],
            ],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Tested (lab-validated)", "color": COLORS["covered"]},
            {"label": "Experimental (pending test)", "color": COLORS["experimental"]},
            {"label": "No coverage", "color": COLORS["uncovered"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#e8e8e8",
        "selectTechniquesAcrossTactics": True,
        "selectSubTechniquesWithParent": False,
        "selectVisibleTechniques": True,
        "metadata": [
            {
                "name": "project",
                "value": "OT Sentinel",
            },
            {
                "name": "author",
                "value": "Subhash Bharadwaj",
            },
            {
                "name": "techniques_covered",
                "value": str(len(coverage)),
            },
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"Navigator layer written to: {output_path}")
    print(f"Techniques covered: {len(coverage)}")
    print(f"Techniques in matrix: {sum(len(v) for v in ICS_TECHNIQUES.values())}")


def main():
    repo_root = Path(__file__).resolve().parent.parent
    rules_dir = repo_root / "rules"
    output_path = repo_root / "mappings" / "coverage_heatmap.json"

    if len(sys.argv) > 1 and sys.argv[1] == "--output":
        output_path = Path(sys.argv[2])

    print("OT Sentinel — ATT&CK Navigator Layer Generator")
    print("-" * 50)

    coverage = extract_mitre_ids_from_rules(rules_dir)
    generate_navigator_layer(coverage, output_path)

    if coverage:
        print("\nCovered techniques:")
        for tid, status in sorted(coverage.items()):
            print(f"  {tid}: {status}")
    else:
        print("\nNo rules found with MITRE ATT&CK mappings.")


if __name__ == "__main__":
    main()
