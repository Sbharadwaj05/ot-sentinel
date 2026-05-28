# OT Sentinel — Complete Project Plan
### Open-Source Detection Rules for ICS/OT Protocols
**Version 1.0 | Author: Subhash Bharadwaj | May 2026**

---

## 1. Vision & Mission

### What is OT Sentinel?
OT Sentinel is an open-source detection rule library for Industrial Control System (ICS) and Operational Technology (OT) environments. It provides Wazuh and Sigma-compatible detection rules targeting the most exploited OT protocols, tested against a real OpenPLC + GNS3 digital twin lab, with full MITRE ATT&CK for ICS mapping.

### The Problem It Solves
The OT/ICS security space is critically underserved in open-source tooling:
- Most detection rulesets are vendor-locked (Claroty, Dragos, Nozomi) or cost tens of thousands of dollars
- Free rulesets that exist are unmaintained, untested, and lack ATT&CK for ICS mapping
- SOC analysts in industrial environments have no practical starting point
- Wazuh is widely deployed but has near-zero community content for OT protocols
- Nobody has published rules tested against an actual working digital twin

### The Unique Moat
This repo exists at the intersection of three things almost nobody combines publicly:
1. OT protocol knowledge (Modbus, DNP3, IEC 104, MQTT, OPC-UA)
2. Detection engineering expertise (Wazuh, Sigma, ATT&CK for ICS)
3. A real digital twin lab (OpenPLC + GNS3) for validated testing

---

## 2. Target Audience

| Audience | Why They Care |
|---|---|
| SOC analysts in industrial companies | Ready-to-deploy rules with zero vendor cost |
| OT security engineers | Validated test cases and ATT&CK mapping |
| Red teamers / pentesters | Understand what detections exist (inverse use) |
| Security researchers | Reference implementation for OT detection |
| Students / learners | Lab setup guide + learning resource |
| Hiring managers in DE/JP | Public proof of rare OT security skill set |

---

## 3. Protocol Coverage Matrix

### Phase 1 Protocols (Core — Ship First)
| Protocol | Port | Used In | Attack Surface |
|---|---|---|---|
| Modbus TCP | 502 | PLCs, RTUs, sensors | Coil writes, register manipulation, unauthorized reads |
| DNP3 | 20000 | Electric utilities, water | Unsolicited responses, replay, auth bypass |
| IEC 60870-5-104 | 2404 | Power grids, substations | Unauthorized commands, ASDU spoofing |
| MQTT | 1883/8883 | IIoT sensors, gateways | Topic injection, broker abuse, no-auth connections |

### Phase 2 Protocols (Extended)
| Protocol | Port | Used In | Attack Surface |
|---|---|---|---|
| OPC-UA | 4840 | Multi-vendor SCADA | Session hijacking, node enumeration, write abuse |
| EtherNet/IP | 44818 | Rockwell PLCs | Identity object abuse, I/O command injection |
| BACnet | 47808 | Building automation | Unauthenticated device discovery, property writes |
| PROFINET | Dynamic | Siemens environments | DCP flooding, device impersonation |

---

## 4. Attack Pattern Catalog

### 4.1 Modbus Attack Patterns
| Attack | Description | Detection Approach |
|---|---|---|
| Unauthorized Coil Write | FC05/FC15 writes from unexpected source IP | Source IP allowlist deviation |
| Mass Register Read | FC03 bulk reads — reconnaissance pattern | Abnormal read volume per time window |
| Illegal Function Code | FC > 127 — fuzzing indicator | Function code range validation |
| Rapid Polling | Polling rate >> baseline — DoS or fuzzing | Request rate threshold per source |
| Rogue Master | New Modbus master IP never seen before | First-seen source IP alert |
| Exception Response Flood | Repeated exception responses — scanning | Exception response rate threshold |

### 4.2 DNP3 Attack Patterns
| Attack | Description | Detection Approach |
|---|---|---|
| Unsolicited Response Abuse | Forged unsolicited responses from rogue outstation | Unexpected outstation address |
| DNP3 Replay Attack | Retransmission of captured DNP3 frames | Sequence number regression |
| Direct Operate Abuse | Unauthorized control object operations | CROB operations from unauthed source |
| Authentication Bypass | DNP3 SA challenge-response manipulation | Auth failure rate threshold |
| Broadcast Message Abuse | Broadcast address (0xFFFF) commands | Destination address = broadcast alert |

### 4.3 IEC 104 Attack Patterns
| Attack | Description | Detection Approach |
|---|---|---|
| Unauthorized STARTDT | Connection initiation from unknown IP | Source IP not in allowlist |
| ASDU Spoofing | Fake data objects injected mid-session | IOA value anomaly detection |
| C_SC_NA Command Injection | Single command to switch breakers etc | Command type from non-master |
| Interrogation Abuse | Mass GI commands — recon pattern | GI frequency threshold |
| TESTFR Flooding | Test frame flood causing session instability | TESTFR rate per minute |

### 4.4 MQTT Attack Patterns
| Attack | Description | Detection Approach |
|---|---|---|
| Anonymous Connection | CONNECT without credentials | username field null/empty |
| Wildcard Topic Subscription | Sub to # — mass data harvest | Topic pattern = # or +/# |
| Retained Message Poisoning | Malicious retained msg on critical topic | Retain flag on sensitive topics |
| High-Frequency Publish | Sensor flooding — DoS or exfil | Publish rate threshold per client |
| Unexpected Broker Connection | New client ID never seen before | First-seen client ID alert |
| QoS 0 Credential Topics | Auth data sent at QoS 0 — interception risk | Credential topics at QoS 0 |

---

## 5. MITRE ATT&CK for ICS Mapping

Every rule in OT Sentinel maps to the ICS ATT&CK matrix (not Enterprise — the ICS-specific one).

### Primary Techniques Covered
| Technique ID | Name | Protocols Covered |
|---|---|---|
| T0855 | Unauthorized Command Message | Modbus, DNP3, IEC 104 |
| T0836 | Modify Parameter | Modbus, OPC-UA |
| T0843 | Program Download | DNP3, EtherNet/IP |
| T0856 | Spoof Reporting Message | DNP3, IEC 104 |
| T0838 | Modify Alarm Settings | OPC-UA, BACnet |
| T0803 | Block Command Message | All protocols |
| T0831 | Manipulation of Control | Modbus, DNP3 |
| T0832 | Manipulation of View | IEC 104, OPC-UA |
| T0846 | Remote System Discovery | All protocols (scanning) |
| T0888 | Remote System Information Discovery | Modbus, DNP3 |
| T0869 | Standard Application Layer Protocol | MQTT, OPC-UA |
| T0814 | Denial of Service | All protocols (flooding) |

### Tactic Coverage
- Initial Access: Partial (network-facing protocol exposure)
- Execution: T0855, T0843
- Persistence: T0836
- Evasion: T0856, T0832
- Discovery: T0846, T0888
- Lateral Movement: Protocol pivoting patterns
- Inhibit Response Function: T0803, T0838, T0814
- Impair Process Control: T0831, T0836

---

## 6. Repository Structure

```
ot-sentinel/
├── README.md                          # Main landing page
├── CONTRIBUTING.md                    # How to add rules
├── LICENSE                            # Apache 2.0
├── DISCLAIMER.md                      # Independent community project
├── docs/
│   ├── lab-setup/
│   │   ├── openplc-setup.md           # OpenPLC installation guide
│   │   ├── gns3-topology.md           # GNS3 network topology
│   │   ├── wazuh-agent-config.md      # Wazuh config for OT monitoring
│   │   └── network-diagram.png        # Visual lab topology
│   ├── protocol-guides/
│   │   ├── modbus-primer.md           # Modbus for detection engineers
│   │   ├── dnp3-primer.md
│   │   ├── iec104-primer.md
│   │   └── mqtt-primer.md
│   └── attack-catalog/
│       ├── modbus-attacks.md
│       ├── dnp3-attacks.md
│       └── iec104-attacks.md
├── rules/
│   ├── wazuh/
│   │   ├── modbus/
│   │   │   ├── modbus_unauthorized_write.xml
│   │   │   ├── modbus_rogue_master.xml
│   │   │   ├── modbus_illegal_function.xml
│   │   │   └── modbus_rapid_polling.xml
│   │   ├── dnp3/
│   │   ├── iec104/
│   │   ├── mqtt/
│   │   └── opc-ua/
│   └── sigma/
│       ├── modbus/
│       ├── dnp3/
│       ├── iec104/
│       └── mqtt/
├── tests/
│   ├── README.md                      # How to run tests
│   ├── framework/
│   │   ├── test_runner.py             # Automated test harness
│   │   └── validator.py              # Rule validation
│   ├── modbus/
│   │   ├── test_unauthorized_write.py
│   │   └── expected_alerts.json
│   ├── dnp3/
│   └── iec104/
├── cdb-lists/
│   ├── authorized_modbus_masters.txt
│   ├── authorized_dnp3_outstations.txt
│   └── known_mqtt_clients.txt
├── mappings/
│   ├── attack_ics_matrix.json         # Full ATT&CK for ICS mapping
│   └── coverage_heatmap.json          # Navigator layer file
└── tools/
    └── generate_navigator_layer.py    # ATT&CK Navigator export
```

---

## 7. Rule Format Standard

### Every Wazuh Rule Must Include
```xml
<!--
  Rule: OT-SENTINEL-MOD-001
  Protocol: Modbus TCP
  Attack Pattern: Unauthorized Coil Write
  ATT&CK for ICS: T0855 - Unauthorized Command Message
  Severity: High
  Tested: Yes (OpenPLC + GNS3 lab)
  Author: Subhash Bharadwaj
  Version: 1.0
-->
<rule id="200001" level="12">
  <decoded_as>json</decoded_as>
  <field name="protocol">modbus</field>
  <field name="function_code">^(5|15)$</field>
  <not_same_field>source_ip</not_same_field>
  <list field="source_ip" lookup="not_match_key">
    cdb-lists/authorized_modbus_masters
  </list>
  <description>OT Sentinel: Unauthorized Modbus coil write from unknown master $(source_ip)</description>
  <mitre>
    <id>T0855</id>
  </mitre>
  <group>ot-sentinel,modbus,unauthorized_command,high_severity</group>
</rule>
```

### Every Sigma Rule Must Include
```yaml
title: OT Sentinel - Unauthorized Modbus Coil Write
id: ot-sentinel-mod-001
status: experimental
description: Detects unauthorized Modbus coil write from unknown master device
references:
  - https://github.com/YOUR_HANDLE/ot-sentinel
  - https://attack.mitre.org/techniques/ics/T0855/
author: Subhash Bharadwaj
date: 2026/05/27
tags:
  - attack.ics.t0855
  - ot.modbus
logsource:
  product: wazuh
  category: ot_protocol
detection:
  selection:
    protocol: modbus
    function_code|in:
      - 5
      - 15
  filter_authorized:
    source_ip|in:
      - <authorized_masters_list>
  condition: selection and not filter_authorized
falsepositives:
  - New authorized master added without updating allowlist
level: high
```

---

## 8. Lab Architecture

### 8.1 OpenPLC Setup
- OpenPLC Runtime v3 simulating a PLC on a Linux VM
- Ladder logic programs simulating:
  - Water pump control (Modbus)
  - Substation breaker control (DNP3/IEC 104)
  - Temperature sensor network (MQTT)
- OpenPLC editor for modifying ladder logic for attack simulation

### 8.2 GNS3 Network Topology
```
[Attacker VM] ----+
                  |
[HMI Simulator] --+---- [GNS3 Switch] ---- [OpenPLC Runtime]
                  |              |
[Wazuh Agent] ----+    [Network TAP/Mirror]
                               |
                        [Wazuh Manager]
                               |
                        [Wazuh Dashboard]
```

### 8.3 Traffic Generation for Testing
- **Modbus:** pymodbus library for crafting attack traffic
- **DNP3:** OpenDNP3 library (C++/Python bindings)
- **IEC 104:** lib60870 (open source IEC 60870-5-104 library)
- **MQTT:** Paho MQTT client + Mosquitto broker
- **Packet capture:** tcpdump + Wireshark for validation

### 8.4 Wazuh Integration
- Wazuh agent on the network TAP VM
- Custom decoder for each OT protocol
- Rules imported from ot-sentinel repo
- Dashboard panels for OT-specific alerts

---

## 9. Development Phases & Timeline

### Phase 0 — Foundation (Week 1, ~4 hours)
- [ ] Create GitHub repo with full structure
- [ ] Write README with vision, lab setup overview, protocol matrix
- [ ] Write CONTRIBUTING.md and DISCLAIMER
- [ ] Set up CI/CD: GitHub Actions for rule validation on PR
- [ ] Create ATT&CK Navigator layer template

### Phase 1 — Modbus (Weekend 1, ~6 hours)
Target: 8 rules covering the most critical Modbus attack patterns
- [ ] OT-SENTINEL-MOD-001: Unauthorized coil write
- [ ] OT-SENTINEL-MOD-002: Unauthorized register write
- [ ] OT-SENTINEL-MOD-003: Rogue master detection
- [ ] OT-SENTINEL-MOD-004: Illegal function code
- [ ] OT-SENTINEL-MOD-005: Mass register read (recon)
- [ ] OT-SENTINEL-MOD-006: Rapid polling detection
- [ ] OT-SENTINEL-MOD-007: Exception response flood
- [ ] OT-SENTINEL-MOD-008: Modbus over non-standard port
- [ ] Write Modbus protocol primer doc
- [ ] Write test cases for all 8 rules
- [ ] Test all rules in OpenPLC + GNS3 lab
- [ ] Update ATT&CK coverage heatmap

### Phase 2 — DNP3 (Weekend 2, ~6 hours)
Target: 7 rules for DNP3 attack patterns
- [ ] OT-SENTINEL-DNP-001: Unsolicited response from rogue outstation
- [ ] OT-SENTINEL-DNP-002: Direct operate without authorization
- [ ] OT-SENTINEL-DNP-003: DNP3 broadcast command abuse
- [ ] OT-SENTINEL-DNP-004: Authentication challenge failure spike
- [ ] OT-SENTINEL-DNP-005: Sequence number regression (replay)
- [ ] OT-SENTINEL-DNP-006: Unknown data link address
- [ ] OT-SENTINEL-DNP-007: Mass data request (recon)
- [ ] Write DNP3 protocol primer doc
- [ ] Test all rules in lab

### Phase 3 — IEC 104 (Weekend 3, ~5 hours)
Target: 6 rules for IEC 104
- [ ] OT-SENTINEL-IEC-001: Unauthorized STARTDT from unknown IP
- [ ] OT-SENTINEL-IEC-002: C_SC_NA single command injection
- [ ] OT-SENTINEL-IEC-003: C_DC_NA double command injection
- [ ] OT-SENTINEL-IEC-004: General interrogation abuse
- [ ] OT-SENTINEL-IEC-005: TESTFR flooding
- [ ] OT-SENTINEL-IEC-006: ASDU IOA anomaly
- [ ] Write IEC 104 protocol primer doc
- [ ] Test all rules in lab

### Phase 4 — MQTT + OPC-UA (Weekend 4, ~6 hours)
Target: 8 rules across MQTT and OPC-UA
- [ ] OT-SENTINEL-MQTT-001 through 005 (anonymous connect, wildcard sub, retained msg poison, flood, rogue client)
- [ ] OT-SENTINEL-OPC-001 through 003 (session hijack, node enumeration, unauthorized write)
- [ ] Test all rules in lab

### Phase 5 — Polish & Launch (Weekend 5)
- [ ] Complete lab setup documentation (step-by-step)
- [ ] Generate final ATT&CK Navigator coverage layer
- [ ] Write detailed README with coverage table, usage guide, screenshots
- [ ] Record a short demo video (optional but high impact)
- [ ] Reddit post: r/OTSecurity, r/Wazuh, r/netsec, r/SCADA
- [ ] LinkedIn post
- [ ] Tag Wazuh official, ICS-CERT on socials

---

## 10. Rule Naming Convention

```
OT-SENTINEL-[PROTOCOL]-[NUMBER]

Protocols:
  MOD = Modbus
  DNP = DNP3
  IEC = IEC 60870-5-104
  MQT = MQTT
  OPC = OPC-UA
  EIP = EtherNet/IP
  BAC = BACnet
  PRO = PROFINET

Example: OT-SENTINEL-MOD-001
```

Wazuh rule IDs: Start at 200001 (avoids conflict with built-in Wazuh rules)

---

## 11. CI/CD Pipeline

### GitHub Actions on every PR
```yaml
name: Validate OT Sentinel Rules
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Validate Wazuh XML syntax
        run: python tools/validate_xml.py rules/wazuh/
      - name: Validate Sigma YAML
        run: sigma check rules/sigma/
      - name: Check ATT&CK IDs exist
        run: python tools/validate_attack_ids.py
      - name: Verify rule naming convention
        run: python tools/check_naming.py
```

---

## 12. Documentation Strategy

Each protocol folder gets:
1. A primer doc explaining the protocol for detection engineers (not operators)
2. An attack catalog with Wireshark screenshots of real attack traffic
3. A "how to test this rule" section with exact commands
4. A "false positives" guide

The goal: someone with zero OT background can read the docs and understand what they're detecting and why.

---

## 13. Community & Growth Strategy

### Launch Sequence
1. Post on **r/Wazuh** first (existing audience, you're already known)
2. Cross-post to **r/OTSecurity** and **r/SCADA**
3. **r/netsec** with the angle of "open-source ICS detection rules"
4. LinkedIn post with the Germany/Japan angle (rare specialization)
5. Tag **@wazuh** on Twitter/X

### Buy Me A Coffee Setup
- Add sponsor button to GitHub once repo hits 50 stars
- Tiers: Coffee (one-time), Monthly (access to "tested configs" branch)

### Long-term Growth
- Add new protocol every quarter
- Accept community-contributed rules (with review)
- Partner with ICS-focused CTF creators (ICS CTF rules as bonus content)
- Eventually: submit a talk to DEF CON ICS Village or S4 Conference

---

## 14. Career Positioning Notes

This repo directly enables:
- **Job applications in DE/JP:** Siemens, Bosch, Mitsubishi Electric, Yokogawa, ABB all run OT security teams. A public repo with tested OT detection rules is a portfolio piece almost no candidate has.
- **Upwork/freelance:** OT security assessments start at $150/hr. The repo is credibility.
- **Conference talks:** "I built and tested these rules against a real digital twin" is a conference talk abstract that writes itself.
- **Resume line:** "Authored OT Sentinel, open-source ICS detection rule library for Wazuh/Sigma covering 5 OT protocols, X GitHub stars"

---

## 15. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Rules being used offensively | Add DISCLAIMER.md, license as Apache 2.0, document for defense only |
| Parivartan claiming CPE knowledge is their IP | All rules are independently written. OpenPLC and GNS3 are public tools. No proprietary code. |
| Low traction | r/Wazuh existing audience + cross-posting to r/OTSecurity mitigates cold start |
| Protocol knowledge gaps | OpenPLC + GNS3 lab forces you to actually understand the traffic before writing rules |

---

*"The only open-source OT detection library tested against a real digital twin."*
