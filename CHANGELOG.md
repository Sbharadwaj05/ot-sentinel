# Changelog

All notable changes to OT Sentinel are documented in this file.

---

## [v1.0.0] — 2026-05-30

### Added

- **29 detection rules** across 5 ICS/OT protocols:
  - Modbus TCP (8 rules): unauthorized writes, rogue master, fuzzing, recon, DoS, evasion
  - DNP3 (7 rules): rogue outstation, direct operate, broadcast abuse, auth spike, replay, recon
  - IEC 60870-5-104 (6 rules): unauthorized STARTDT, command injection, GI abuse, TESTFR flood, IOA anomaly
  - MQTT (5 rules): anonymous connect, wildcard sub, retained poisoning, publish flood, rogue client
  - OPC-UA (3 rules): session hijack, node enumeration, unauthorized write
- **Wazuh XML rules** with MITRE ATT&CK for ICS mapping (rule IDs 200001-200039)
- **Sigma YAML rules** for SIEM-agnostic deployment
- **12 CDB allowlists** for IPs, device IDs, client IDs, topics, and ports
- **5 protocol primers** written for security engineers (not OT operators)
- **5 attack catalogs** documenting detection logic for each pattern
- **8 Modbus test scripts** (pymodbus-based, real OpenPLC interaction)
- **modbus_tap.py** — Modbus TCP traffic monitor (live capture, pcap replay, demo mode)
- **CI/CD pipeline** — XML/YAML validation, ATT&CK ID checker, naming convention checker
- **ATT&CK Navigator layer** — coverage heatmap for ICS matrix
- **Lab setup guide** — OpenPLC VM, GNS3 topology, Wazuh agent config
- **Testing guide** — Tier 1 (8 Modbus rules) + Tier 2 (one per protocol)
- **Getting Started guide** — 6-step onboarding for OT beginners
- **Wazuh 4.14 compatibility guide** — symptom/fix map, verified test results
- **Contributing guide** with good-first-issue suggestions

### Verified

- All 8 Modbus rules tested against OpenPLC on real hardware (FC write, read, exception)
- All 29 rules validated in Wazuh 4.14.5 via `wazuh-logtest`
- 1 rule per protocol (DNP3/IEC104/MQTT/OPC-UA) validated in Wazuh 4.14.5
- CI pipeline: 34 XML files, 29 YAML files, all ATT&CK IDs pass validation
- ATT&CK for ICS coverage: 7 techniques (T0814, T0836, T0840, T0846, T0855, T0856, T0858)

### Known Limitations

- Frequency-based rules (MOD-005/006/007) require sustained traffic for `if_matched_sid` testing
- DNP3/IEC104/MQTT/OPC-UA test scripts are stubs (test directories exist, scripts pending)
- DNP3 sequence number regression (DNP-005) uses heuristic detection; true replay detection requires stateful tracking
- OPC-UA session hijacking (OPC-001) requires CDB list tuning per deployment

---

*OT Sentinel — Changelog*
