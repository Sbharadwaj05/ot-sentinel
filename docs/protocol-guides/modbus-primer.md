# Modbus Protocol Primer for Detection Engineers

> **Target audience**: SOC analysts and detection engineers who understand security but need a crash course in Modbus for writing detection rules.
> **Prerequisites**: Basic TCP/IP knowledge. No prior OT/ICS experience required.

---

## 1. What is Modbus?

Modbus is the most widely deployed industrial communication protocol — the "HTTP of the industrial world." Published by Modicon (now Schneider Electric) in 1979, it remains dominant in:

- Water/wastewater treatment plants
- Power generation and distribution
- Oil and gas pipelines
- Building automation (HVAC, elevators)
- Manufacturing assembly lines

**Key property for detection**: Modbus has **no authentication, no encryption, and no integrity checks**. Every security control must come from the network layer. If you can reach a Modbus device on TCP port 502, you can read and write to it.

---

## 2. Modbus Variants

| Variant | Transport | Port | Use Case |
|---------|-----------|------|----------|
| **Modbus TCP** | TCP/IP | 502 | Ethernet-based SCADA networks |
| **Modbus RTU** | Serial (RS-232/485) | N/A | Direct device-to-device wiring |
| **Modbus ASCII** | Serial (RS-232/485) | N/A | Legacy installations |

**OT Sentinel focuses on Modbus TCP** — this is what you'll see in modern networked SCADA environments and what reaches your SIEM.

---

## 3. The Modbus Data Model

Modbus organizes data into four tables. Each table has 16-bit registers addressed from 0–65535.

| Table | Data Type | Access | Example Use |
|-------|-----------|--------|-------------|
| **Coils** | Single bit (1/0) | Read-Write | Motor on/off, valve open/closed |
| **Discrete Inputs** | Single bit (1/0) | Read-Only | Limit switch state, sensor alarm |
| **Holding Registers** | 16-bit word | Read-Write | Set-points, runtime parameters |
| **Input Registers** | 16-bit word | Read-Only | Temperature, pressure, flow rate |

**Detection impact**: 
- Writes to coils (FC05/FC15) and holding registers (FC06/FC16) = potential unauthorized control
- Bulk reads from multiple tables = reconnaissance
- Writing to input registers or discrete inputs = impossible (devices reject this, but it can be a fuzzing indicator)

---

## 4. Function Codes — The Detection Cheat Sheet

Function codes are the *most important field for detection*. They tell you exactly what action is being performed.

### Critical Function Codes (Always Alert)

| FC | Name | Why It Matters |
|----|------|----------------|
| **05** | Write Single Coil | Direct control action — turn something on/off |
| **06** | Write Single Register | Change a parameter — alter set-point, threshold |
| **15** | Write Multiple Coils | Bulk control — change multiple outputs at once |
| **16** | Write Multiple Registers | Bulk parameter change — reprogram device behavior |

### Suspicious Function Codes (Alert with Context)

| FC | Name | Why It Matters |
|----|------|----------------|
| **01** | Read Coils | Normal in small numbers; recon in bulk |
| **02** | Read Discrete Inputs | Normal; high volume = discovery |
| **03** | Read Holding Registers | Most common; bulk reads = recon |
| **04** | Read Input Registers | Normal; bulk reads = recon |
| **07** | Read Exception Status | Rare in normal ops; often fuzzing |
| **08** | Diagnostics | Rare; can be used for denial-of-service |
| **11** | Get Comm Event Counter | Rare; recon activity |
| **17** | Report Server ID | Rare; device fingerprinting |

### Illegal / Fuzzing Indicators

| FC Range | Meaning |
|----------|---------|
| **0** | Reserved — never valid |
| **72–119** | Reserved — never valid |
| **128–255** | Exception responses (FC + 0x80) — but only valid in responses |

**Detection rule**: Any function code outside {1–8, 11, 15–17, 20–24, 43} is a fuzzing indicator or protocol violation.

---

## 5. Normal vs. Malicious Traffic Patterns

### Normal Modbus Traffic

```
SCADA Server (192.168.1.10) → PLC (192.168.1.100):
  - FC03 reads every 1–5 seconds (holding registers for dashboard)
  - FC04 reads every 10–30 seconds (input registers for trending)
  - FC05/FC06 writes: rare (only during operator actions)
  - Transaction IDs increment predictably
  - Single master, multiple slaves
```

### Reconnaissance Traffic (Pre-Attack)

```
Unknown Host (DHCP new) → PLC (192.168.1.100):
  - FC01, FC02, FC03, FC04 — rapid reads across address ranges
  - FC17 (Report Server ID) calls
  - FC11 (Get Comm Event Counter) calls
  - High volume: 100+ function code calls in < 10 seconds
  - Scanning multiple unit IDs
```

### Attack Traffic

```
Attacker (192.168.1.200) → PLC (192.168.1.100):
  - FC05/FC15 writes from unknown source IP
  - FC06/FC16 writes modifying critical registers
  - FC05 toggling coils rapidly (DoS via actuator wear)
  - FC08 diagnostic sub-functions (force listen-only mode)
  - FC outside valid range (fuzzing/exploit attempt)
  - Exception responses in requests (protocol abuse)
```

---

## 6. Fields to Extract for Detection

When monitoring Modbus traffic, your decoder must extract these fields:

| Field | Type | Detection Use |
|-------|------|---------------|
| `source_ip` | IP address | Allowlist check, first-seen detection |
| `destination_ip` | IP address | Asset inventory, vulnerability context |
| `function_code` | integer (0–255) | Primary detection condition |
| `unit_id` | integer (0–247) | Target device identification |
| `transaction_id` | integer | Replay detection, sequence gaps |
| `reference_number` | integer | Which coil/register is being accessed |
| `data` | string/hex | What value is being written |
| `event_type` | "request" or "response" | Directional analysis |

---

## 7. Wireshark Filters for Analysis

Use these display filters to analyze Modbus captures:

```
# All Modbus traffic
modbus

# Only write commands (RW = real work)
modbus.func_code in {5 6 15 16}

# Only read commands
modbus.func_code in {1 2 3 4}

# Write to coil #0 from any source
modbus.func_code == 5 && modbus.reference_num == 0

# Unusual function codes (fuzzing)
modbus.func_code > 72 && modbus.func_code < 128

# Traffic from a specific suspicious IP
ip.src == 192.168.1.200 && modbus
```

---

## 8. OT Sentinel's Modbus Rule Strategy

| Rule ID | Attack Pattern | Detection Logic |
|---------|---------------|-----------------|
| MOD-001 | Unauthorized Coil Write | FC05/FC15 + source_ip NOT in CDB allowlist |
| MOD-002 | Unauthorized Register Write | FC06/FC16 + source_ip NOT in CDB allowlist |
| MOD-003 | Rogue Master Detection | First-seen source_ip on Modbus port |
| MOD-004 | Illegal Function Code | FC not in valid range |
| MOD-005 | Mass Register Read (Recon) | FC03 rate > threshold per time window |
| MOD-006 | Rapid Polling | Request rate > baseline per source |
| MOD-007 | Exception Response Flood | FC > 127 + rate > threshold |
| MOD-008 | Diagnostics Abuse | FC08 + suspicious sub-function codes |

---

## 9. References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus TCP/IP Implementation Guide](https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)
- [MITRE ATT&CK for ICS — T0855: Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/)
- [MITRE ATT&CK for ICS — T0836: Modify Parameter](https://attack.mitre.org/techniques/ics/T0836/)

---

*OT Sentinel — Phase 1: Modbus Detection Rules*
