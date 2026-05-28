# OT Sentinel — Open-Source Detection Rules for ICS/OT Protocols

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-29-blue)](rules/)
[![ATT&CK](https://img.shields.io/badge/ATT&CK%20ICS-7%20techniques-orange)](mappings/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen)]()
[![Lab](https://img.shields.io/badge/lab-OpenPLC%2BGNS3-informational)]()

**OT Sentinel** is an open-source detection rule library for Industrial Control Systems (ICS) and Operational Technology (OT) protocols. It provides ready-to-deploy **Wazuh** and **Sigma** rules backed by MITRE ATT&CK for ICS, tested against a real OpenPLC + GNS3 digital twin lab.

---

## The Problem

OT/ICS security teams face a critical gap:

- **No open-source detection rules exist** for OT protocols (Modbus, DNP3, IEC 104, MQTT, OPC-UA) on major SIEM/XDR platforms
- Commercial OT security tools cost $50K–$200K+ per site
- Existing rules are proprietary, locked behind vendor contracts
- Small water treatment plants, power substations, and factories are left blind

**OT Sentinel fills this gap** — free, open-source, lab-tested detection rules anyone can deploy with Wazuh (the most popular open-source XDR).

---

## What Makes OT Sentinel Different

| Aspect | OT Sentinel | Other Approaches |
|--------|-------------|------------------|
| **Rules** | Wazuh XML + Sigma YAML — ready to deploy | Proprietary, vendor-locked |
| **Testing** | Lab-tested against real OpenPLC + GNS3 | Often untested, theoretical |
| **Coverage** | 5+ protocols with MITRE ATT&CK for ICS mapping | Single protocol, no mapping |
| **Cost** | Free (Apache 2.0) | $50K+ licensing |
| **Community** | Open-source, extendable, auditable | Closed, opaque |

---

## Protocol Coverage

| Protocol | Port | Rules | Tests | Status |
|----------|------|-------|-------|--------|
| **Modbus TCP** | 502 | 8 Wazuh + 8 Sigma | ✅ Scripted | Complete |
| **DNP3** | 20000 | 7 Wazuh + 7 Sigma | 💤 Stubs | Complete |
| **IEC 60870-5-104** | 2404 | 6 Wazuh + 6 Sigma | 💤 Stubs | Complete |
| **MQTT** | 1883 | 5 Wazuh + 5 Sigma | 💤 Stubs | Complete |
| **OPC-UA** | 4840 | 3 Wazuh + 3 Sigma | 💤 Stubs | Complete |

> 💤 **Stubs** = test directories exist, scripts pending. Contribute one via PR.

---

## Repository Structure

```
ot-sentinel/
├── rules/
│   ├── wazuh/          # Wazuh XML rules (deploy to /var/ossec/etc/rules/)
│   │   ├── decoders/   # Custom Wazuh decoders for OT protocols
│   │   ├── modbus/
│   │   ├── dnp3/
│   │   ├── iec104/
│   │   ├── mqtt/
│   │   └── opc-ua/
│   └── sigma/          # Sigma YAML rules (SIEM-agnostic)
│       ├── modbus/
│       ├── dnp3/
│       ├── iec104/
│       └── mqtt/
├── cdb-lists/           # Wazuh CDB allowlists
├── tests/               # Test scripts (pymodbus, paho-mqtt, etc.)
├── docs/                # Protocol primers, attack catalogs, lab guides
├── mappings/            # ATT&CK for ICS coverage maps
├── tools/               # Validation & CI/CD tooling
└── .github/workflows/   # CI pipeline
```

---

## Quick Start

### Prerequisites

- Wazuh Manager 4.x+
- Python 3.9+ (for test scripts)
- Optional: OpenPLC, GNS3 lab (see [lab setup guide](docs/lab-setup/))

### Deploy Rules

```bash
# Clone the repo
git clone https://github.com/Sbharadwaj05/ot-sentinel.git
cd ot-sentinel

# Copy Wazuh rules to manager
sudo cp rules/wazuh/decoders/*.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/modbus/*.xml /var/ossec/etc/rules/

# Copy CDB lists
sudo cp cdb-lists/* /var/ossec/etc/lists/

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

### Run Tests

```bash
cd tests/modbus/
python test_unauthorized_write.py --target 192.168.1.100 --port 502
```

---

## MITRE ATT&CK for ICS Coverage

Every rule maps to [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/). Current coverage:

| Tactic | Techniques Covered | Rules |
|--------|-------------------|-------|
| Initial Access | — | — |
| Execution | T0855 | 7 |
| Persistence | — | — |
| Evasion | — | — |
| Discovery | T0840, T0846 | 10 |
| Lateral Movement | — | — |
| Collection | — | — |
| Command and Control | — | — |
| Inhibit Response Function | T0858 | 2 |
| Impair Process Control | T0814, T0836, T0855, T0856 | 6 |
| Impact | — | — |

> See [mappings/](mappings/) for the full ATT&CK Navigator layer.

---

## Author

**Subhash Bharadwaj** — Security Engineer  
- Production experience: Wazuh, SIEM/SOAR, Kubernetes (RKE2), Terraform, Ansible
- OT/ICS: OpenPLC, GNS3, air-gapped digital twin environments
- Prior work: [Wazuh NIST Rules Set](https://github.com/Sbharadwaj05/Wazuh-NIST-Rules-Set) — 50 rules, NIST CSF 2.0 + ATT&CK mapped

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Disclaimer

OT Sentinel is an **independent community project**. It is not affiliated with or endorsed by any ICS vendor, government agency, or security product vendor. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

---

**Phase 0 ✅ | Phase 1 ✅ | Phase 2 ✅ | Phase 3 ✅ | Phase 4 ✅ | Next: Phase 5 — Polish & Launch**
