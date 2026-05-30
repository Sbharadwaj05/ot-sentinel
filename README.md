# OT Sentinel — Open-Source Detection Rules for ICS/OT Protocols

> **⚠️ DON'T BREAK THE PLANT**: Community-driven project validated in an OpenPLC lab. Designed for **passive network monitoring**. DO NOT deploy to production OT assets without rigorous testing. Respect OT safety culture — validate everything in a non-production environment first.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-29-blue)](rules/)
[![ATT&CK](https://img.shields.io/badge/ATT&CK%20ICS-7%20techniques-orange)](mappings/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen)]()
[![Lab](https://img.shields.io/badge/lab-OpenPLC%2BWazuh%204.14-informational)]()

**OT Sentinel** is an open-source detection rule library for Industrial Control Systems (ICS) and Operational Technology (OT) protocols. It provides **Wazuh** and **Sigma** rules mapped to MITRE ATT&CK for ICS — built for learning, lab testing, and kickstarting OT detection engineering.

> ⚠️ **Not production-ready yet.** Treat this as an educational resource and detection engineering accelerator. Test everything in your own environment before deploying to live OT networks.
>
> New to OT security? Start with [Getting Started](docs/GETTING_STARTED.md).

---

## The Problem

OT/ICS security teams face a critical gap:

- **No open-source detection rules exist** for OT protocols (Modbus, DNP3, IEC 104, MQTT, OPC-UA) on major SIEM/XDR platforms
- Commercial OT security tools cost $50K–$200K+ per site
- Existing rules are proprietary, locked behind vendor contracts
- Small water treatment plants, power substations, and factories are left blind

**OT Sentinel fills this gap** — free, open-source, lab-validated detection rules for learning, testing, and accelerating your OT detection engineering.

---

## What This Is (and Isn't)

| This IS | This IS NOT |
|---------|-------------|
| A detection engineering accelerator | A drop-in replacement for Dragos/Nozomi/Claroty |
| Lab-validated against real OpenPLC hardware | Production-tested across diverse OT environments |
| A learning resource for OT protocol security | A complete OT security solution |
| A foundation you can build on and customize | A set of rules you should blindly deploy to prod |

> **The honest pitch**: Clone this repo, spin up OpenPLC in a VM, deploy the rules to Wazuh, and in an afternoon you'll understand how OT protocol attacks look at the SIEM layer. That's the value — not the rules themselves, but what you learn deploying them.

---

## Production Readiness

| Protocol | Rules Written | Lab-Tested (OpenPLC) | Wazuh-Validated | Test Scripts |
|----------|-------------|----------------------|-----------------|-------------|
| **Modbus** | 8 | ✅ 8/8 | ✅ 4.14.5 | ✅ All 8 |
| **DNP3** | 7 | — | ✅ 1/7 (logtest) | 💤 Stub READMEs |
| **IEC 104** | 6 | — | ✅ 1/6 (logtest) | 💤 Stub READMEs |
| **MQTT** | 5 | — | ✅ 1/5 (logtest) | 💤 Stub READMEs |
| **OPC-UA** | 3 | — | ✅ 1/3 (logtest) | 💤 Stub READMEs |

> 💤 **Stubs** = test directories exist with wazuh-logtest one-liners. Full pymodbus-style scripts planned for v1.1.
>
> **Before deploying to production**: test every rule against YOUR hardware, tune thresholds to YOUR traffic patterns, and populate all CDB allowlists with YOUR authorized devices.

> **Missing protocols**: PROFINET, EtherNet/IP, BACnet, and HART-IP are not yet covered. See the [Roadmap](ROADMAP.md) for planned additions. Community contributions welcome.

---

## How OT Sentinel Compares

### vs Commercial OT Security

| Concern | Dragos / Nozomi / Claroty | OT Sentinel |
|---------|--------------------------|-------------|
| Logic visible? | ❌ Black box | ✅ Open-source |
| Custom rules? | Limited UI | Full control (XML) |
| Works with Wazuh? | ❌ Separate platform | ✅ Drop-in |
| Auditable? | ❌ No | ✅ Apache 2.0 |
| ATT&CK mapped? | Varies | ✅ Every rule |
| Cost | $50K-200K+/year | Free |

### vs Open-Source Tools

| Tool | Purpose | OT Sentinel's Role |
|------|---------|-------------------|
| [Conpot](https://github.com/mushorg/conpot) | ICS honeypot | Alerts on real device attacks |
| [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) | Passive mapping | Detection after discovery |
| [QuickDraw](https://github.com/digitalbond/QuickDraw) | SNORT rules | SIEM-layer (Wazuh/Sigma) |

---

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
