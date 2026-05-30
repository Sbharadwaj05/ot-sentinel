# Roadmap

## v1.0 (Current) — 5 Protocols, 29 Rules

✅ Modbus TCP (8 rules) — Tested against OpenPLC + Wazuh 4.14.5
✅ DNP3 (7 rules) — 1 rule validated in Wazuh
✅ IEC 60870-5-104 (6 rules) — 1 rule validated in Wazuh
✅ MQTT (5 rules) — 1 rule validated in Wazuh
✅ OPC-UA (3 rules) — 1 rule validated in Wazuh

---

## v1.1 — Test Coverage & Polish

| Task | Priority |
|------|----------|
| Complete test scripts for DNP3 rules (7 scripts) | 🟡 |
| Complete test scripts for IEC 104 rules (6 scripts) | 🟡 |
| Complete test scripts for MQTT rules (5 scripts) | 🟡 |
| Complete test scripts for OPC-UA rules (3 scripts) | 🟡 |
| Add Wireshark screenshots to attack catalogs | 🟢 |
| Add real-world attack context (Oldsmar, Industroyer, TRITON) | 🟢 |
| Test against GNS3 multi-protocol topology | 🟢 |

---

## v1.2 — New Protocols

| Protocol | Rules Target | Standard Port |
|----------|-------------|---------------|
| EtherNet/IP (ENIP/CIP) | 5 rules | 44818 |
| BACnet | 5 rules | 47808 |
| PROFINET | 3 rules | 34964 |

---

## v2.0 — Community & Platform

| Goal | Description |
|------|-------------|
| Community-contributed rules pipeline | PR template, review checklist, maintainer guide |
| Splunk/Elastic deployment guide | Sigma rule conversion with `sigmac` |
| Docker-based lab | One-command lab setup with docker-compose |
| ATT&CK Navigator live layer | Auto-generated from CI pipeline |
| Conference talk | DEF CON ICS Village / S4 Conference submission |

---

## Ideas (Not Scheduled)

- Suricata/Snort companion rules (network-layer detection)
- IEC 61850 (substation automation) rules
- HART-IP rules
- Integration with Caldera for OT attack emulation
- Grafana dashboard for OT Sentinel alerts
- Community rule contest (best new rule wins swag)

---

*Have an idea? Open an issue with the `enhancement` tag.*
