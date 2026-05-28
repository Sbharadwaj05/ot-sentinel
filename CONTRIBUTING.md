# Contributing to OT Sentinel

Thank you for helping build open-source OT/ICS detection rules. This guide covers everything you need to contribute a new rule, test case, or tool.

---

## Code of Conduct

- Write rules from **first principles and public protocol documentation** — never copy proprietary detection content
- Every rule must be independently lab-tested or clearly marked `experimental`
- Be respectful, constructive, and security-conscious

---

## Rule Naming Convention

```
OT-SENTINEL-[PROTOCOL]-[NUMBER]

Protocol codes:
  MOD = Modbus
  DNP = DNP3
  IEC = IEC 60870-5-104
  MQT = MQTT
  OPC = OPC-UA

Examples: OT-SENTINEL-MOD-001, OT-SENTINEL-DNP-003, OT-SENTINEL-IEC-002
```

Wazuh rule IDs start at **200001** (avoids conflict with built-in Wazuh rules 100000–199999).

---

## Adding a New Rule

### Step 1: Plan Your Rule

Before writing code, document:

- **Attack pattern**: What malicious behavior does this detect?
- **MITRE ATT&CK for ICS**: Which technique does it map to? (Use the [ICS matrix](https://attack.mitre.org/matrices/ics/), NOT Enterprise)
- **Detection logic**: What fields, thresholds, and filters will you use?
- **False positive scenarios**: What legitimate traffic might trigger this?

### Step 2: Write the Wazuh Rule

Place it under the correct protocol directory:
```
rules/wazuh/<protocol>/<descriptive_name>.xml
```

Every Wazuh rule must include:

```xml
<!--
  Rule: OT-SENTINEL-XXX-NNN
  Protocol: [Protocol Name and Mode]
  Attack Pattern: [Short Description]
  ATT&CK for ICS: [TXXXX] - [Technique Name]
  Severity: [informational|low|medium|high|critical]
  Tested: [Yes|No]
  Author: [Your Name]
  Version: 1.0
-->
<rule id="200XXX" level="[0-15]">
  <decoded_as>json</decoded_as>
  <!-- Match conditions -->
  <field name="...">...</field>
  <!-- Optional CDB allowlist -->
  <list field="..." lookup="not_match_key">cdb-lists/...</list>
  <description>OT Sentinel: [Human-readable alert with $(dynamic_fields)]</description>
  <mitre>
    <id>[ICS Technique ID]</id>
  </mitre>
  <group>ot-sentinel,[protocol],[attack_category],[severity_level]</group>
</rule>
```

### Step 3: Write the Sigma Rule

Place it under the correct protocol directory:
```
rules/sigma/<protocol>/<descriptive_name>.yml
```

Every Sigma rule must include:

```yaml
title: OT Sentinel - [Attack Description]
id: [UUID or rule-id]          # Use valid UUID or ot-sentinel-xxx-nnn
status: experimental            # Change to "tested" after lab validation
description: [Detailed description]
references:
  - https://github.com/Sbharadwaj05/ot-sentinel
  - https://attack.mitre.org/techniques/ics/[TXXXX]/
author: [Your Name]
date: [YYYY/MM/DD]
tags:
  - attack.ics.[tXXXX]          # Lowercase, dots
  - ot.[protocol]
logsource:
  product: wazuh
  category: ot_protocol
detection:
  selection:
    [field]: [value]
  filter_authorized:
    [field]|in:
      - [allowlist_entry]
  condition: selection and not filter_authorized
falsepositives:
  - [Real-world FP scenario]
level: [informational|low|medium|high|critical]
```

### Step 4: Write the Test Script

Place it under `tests/<protocol>/`:
```
tests/<protocol>/test_<descriptive_name>.py
```

Requirements:
- Self-contained Python script with docstring
- Uses the relevant protocol library (pymodbus, paho-mqtt, etc.)
- Accepts `--target` and `--port` CLI arguments
- Includes a `cleanup()` function to restore normal state
- Comment at the top showing expected Wazuh alert
- Runnable with: `python test_xxx.py --target 192.168.1.100 --port 502`

### Step 5: Add the Expected Alert

Create or update `tests/<protocol>/expected_alerts.json`:

```json
{
  "rule_id": "200001",
  "rule_name": "OT Sentinel - Unauthorized Modbus Coil Write",
  "level": 12,
  "fields": {
    "protocol": "modbus",
    "function_code": "5",
    "source_ip": "<test_source_ip>"
  }
}
```

### Step 6: Update the CDB List (if applicable)

If your rule uses a Wazuh CDB list for allowlisting, add entries to the appropriate file in `cdb-lists/`:

```
# authorized_modbus_masters.txt
# Format: IP:comment
192.168.1.10:Engineering Workstation
192.168.1.11:SCADA Server
```

---

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b rule/mod-004-illegal-function`
3. **Add** your rule + test + expected alert
4. **Run** validation locally:
   ```bash
   python tools/validate_xml.py rules/wazuh/
   python tools/validate_attack_ids.py
   python tools/check_naming.py
   ```
5. **Commit** with message: `feat(rules): add OT-SENTINEL-MOD-004 illegal function code`
6. **Push** and open a PR

CI will automatically validate XML syntax, Sigma YAML syntax, ATT&CK IDs, and naming conventions.

---

## Development Phases

| Phase | Protocol | Status | Rules Target |
|-------|----------|--------|-------------|
| 0-5 | All | ✅ Complete | 29 rules shipped |

---

## Good First Issues

New to OT security? Start here:

| Task | Difficulty | Time | What You'll Learn |
|------|-----------|------|-------------------|
| Write a test script for DNP3 rule | 🟢 Easy | 1-2 hr | DNP3 protocol basics, pymodbus-like libraries |
| Write a test script for MQTT rule | 🟢 Easy | 1 hr | MQTT protocol, paho-mqtt library |
| Improve an attack catalog with Wireshark screenshots | 🟢 Easy | 2 hr | OT protocol analysis, Wireshark filtering |
| Add a new protocol primer (EtherNet/IP, BACnet) | 🟡 Medium | 4-6 hr | New protocol research, technical writing |
| Write a new detection rule for an uncovered ATT&CK technique | 🟡 Medium | 3-4 hr | Rule writing, MITRE ATT&CK ICS mapping |
| Build a new protocol tap (pcap → JSON converter) | 🔴 Hard | 6-8 hr | Packet parsing, scapy, Wazuh log formats |

> Pick any open issue labeled `good first issue` or propose your own.

---

## Need Help?

Open an issue with the `question` tag. Join the discussion on:
- r/OTSecurity
- r/Wazuh
- r/SCADA

---

*Maintained by [Subhash Bharadwaj](https://github.com/Sbharadwaj05)*
