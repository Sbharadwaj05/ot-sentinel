# DNP3 Protocol Primer for Detection Engineers

> **Target audience**: SOC analysts and detection engineers who understand Modbus but need a crash course in DNP3 for writing detection rules.
> **Prerequisites**: Modbus protocol knowledge, basic TCP/IP.

---

## 1. What is DNP3?

**Distributed Network Protocol 3** (DNP3) is the dominant SCADA protocol in electric utilities and water treatment across North America, Australia, and parts of Asia. It was developed by Westronic (now GE/Harris) and standardized as IEEE 1815-2012.

Unlike Modbus (simple, unauthenticated), DNP3 has:
- **Layered architecture** — data link, transport, application layers
- **Event-driven reporting** — outstations can send unsolicited updates
- **Time-stamped data** — critical for post-incident forensics
- **Select-before-operate** — two-step control for safety
- **Secure Authentication v5** — challenge-response (rarely deployed)

**Key property for detection**: DNP3 is more complex than Modbus, which means more attack surface AND more detection opportunities. Every layer provides telemetry you can monitor.

---

## 2. DNP3 Architecture

```
┌────────────────────────────────────┐
│       Application Layer            │  Function codes, objects, IIN
├────────────────────────────────────┤
│       Transport Layer              │  Message segmentation
├────────────────────────────────────┤
│       Data Link Layer              │  Addressing, CRC, sequencing
├────────────────────────────────────┤
│       Physical Layer               │  TCP/UDP (port 20000) or serial
└────────────────────────────────────┘
```

---

## 3. Data Link Layer — The Address Space

Every DNP3 device has a **16-bit data link address** (0–65519). This is separate from the IP address and is the primary device identifier in the protocol.

| Address Range | Meaning |
|---------------|---------|
| 0–65519 | Device addresses |
| 65520–65534 | Reserved |
| **65535 (0xFFFF)** | **Broadcast — ALL devices** |

**Detection impact**:
- Broadcast address (65535) in a command = all devices affected simultaneously
- Unknown source/destination addresses = rogue device or misconfiguration
- Each device has TWO addresses: source (sender) and destination (receiver)

---

## 4. Application Layer — Function Codes

DNP3 function codes define the action. The most important for detection:

### Critical Function Codes (Immediate Alert)

| FC | Hex | Name | Detection Significance |
|----|-----|------|----------------------|
| **5** | 0x05 | Direct Operate | Direct control — no select-before-operate safeguard |
| **6** | 0x06 | Direct Operate No Ack | Same but no confirmation — attacker's choice |
| **13** | 0x0D | Cold Restart | Reboot the PLC/RTU — potential DoS |
| **14** | 0x0E | Warm Restart | Partial restart — potential DoS |

### Suspicious Function Codes (Alert with Context)

| FC | Hex | Name | Detection Significance |
|----|-----|------|----------------------|
| **4** | 0x04 | Operate | After select — but could be unauthorized |
| **3** | 0x03 | Select | First step of select-before-operate |
| **20** | 0x14 | Enable Unsolicited | Attacker wants real-time telemetry feed |
| **21** | 0x15 | Disable Unsolicited | Attacker blinding the SCADA |
| **32** | 0x20 | Authenticate | SA challenge — should be rare |

### Response Function Codes

| FC | Hex | Name | Significance |
|----|-----|------|-------------|
| **129** | 0x81 | Response | Normal response to a request |
| **130** | 0x82 | Unsolicited Response | Device-initiated update **without a request** |
| **131** | 0x83 | Auth Response | SA challenge response |

**Detection rule**: FC 0x82 (Unsolicited Response) from an unknown outstation = rogue device injecting false telemetry.

---

## 5. Internal Indications (IIN)

Every DNP3 response contains a 16-bit **Internal Indications** field (two bytes: IIN1 and IIN2). These flags report device state and errors.

| Byte | Bit | Flag | Detection Use |
|------|-----|------|---------------|
| IIN1 | 0 | BROADCAST | Broadcast message received |
| IIN1 | 1 | CLASS_1_EVENTS | Device has unread events |
| IIN1 | 3 | NEED_TIME | Clock not synced — possible time manipulation |
| IIN1 | 6 | DEVICE_RESTART | Device restarted — possible DoS recovery |
| IIN2 | 0 | AUTH_FAIL | **SA authentication failed** |

**Detection rule**: Monitor `DEVICE_RESTART` for unexpected reboots (possible attack). Monitor `AUTH_FAIL` for SA brute-force.

---

## 6. Normal vs. Malicious Traffic

### Normal DNP3 Traffic

```
SCADA (addr 200) → RTU (addr 1):
  - FC 0x01 (Read) every 2-5 seconds for Class 0 poll
  - FC 0x02 (Write) for time synchronization (hourly)
  - FC 0x05/0x06 (Direct Operate): VERY rare — only during operator actions
  - Sequence numbers increment 0-63 then wrap
  - Unsolicited responses from known outstations during events
```

### Reconnaissance Traffic

```
Unknown IP → RTU (addr 1):
  - FC 0x01 mass reads across all object groups
  - FC 0x82 solicitations (requesting unsolicited responses)
  - Multiple requests to different device addresses (scanning)
  - High volume: 100+ reads in < 5 minutes
```

### Attack Traffic

```
Attacker → RTU:
  - FC 0x05 Direct Operate with CROB (control relay) objects
  - FC 0x0D Cold Restart to reboot devices
  - FC 0x15 Disable Unsolicited to blind the SCADA
  - FC 0x82 Unsolicited Response from rogue address (false telemetry)
  - Data link destination = 0xFFFF (broadcast to ALL devices)
  - Replayed packets with sequence number regression
  - Auth spike — multiple FC 0x20/0x83 in short window
```

---

## 7. Fields to Extract for Detection

| Field | Type | Use |
|-------|------|-----|
| `data_link_source` | integer (0-65535) | Who sent this — allowlist check |
| `data_link_destination` | integer (0-65535) | Who receives — broadcast check |
| `function_code` | integer | Primary detection condition |
| `sequence_number` | integer (0-63) | Replay detection |
| `internal_indications` | hex string | Device state flags |
| `object_group` | integer | What data type is being accessed |
| `object_variation` | integer | Specific format of the data |
| `event_type` | "request"/"response" | Directional analysis |

---

## 8. OT Sentinel's DNP3 Rule Strategy

| Rule ID | Attack Pattern | Detection Logic |
|---------|---------------|-----------------|
| DNP-001 | Unsolicited Response from Rogue Outstation | FC 0x82 + outstation addr NOT in CDB list |
| DNP-002 | Direct Operate without Auth | FC 0x05/0x06 + source IP NOT in CDB list |
| DNP-003 | Broadcast Command Abuse | Data link dest >= 65520 |
| DNP-004 | Auth Failure Spike | FC 0x20/0x83 frequency > threshold |
| DNP-005 | Sequence Number Regression (Replay) | Seq 0-2 frequency > threshold |
| DNP-006 | Unknown Data Link Address | Source/dest addr NOT in CDB list |
| DNP-007 | Mass Data Read (Recon) | FC 0x01 frequency > threshold |

---

## 9. References

- [IEEE 1815-2012 — DNP3 Standard](https://standards.ieee.org/standard/1815-2012.html)
- [DNP3 Application Note AN2013-001 — DNP3 Security](https://www.dnp.org/)
- [MITRE ATT&CK for ICS — T0855: Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/)
- [MITRE ATT&CK for ICS — T0856: Spoof Reporting Message](https://attack.mitre.org/techniques/ics/T0856/)

---

*OT Sentinel — Phase 2: DNP3 Detection Rules*
