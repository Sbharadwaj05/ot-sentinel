# Modbus Attack Catalog

> Complete catalog of Modbus TCP attack patterns covered by OT Sentinel detection rules.
> Each entry includes the attack description, detection approach, MITRE ATT&CK for ICS mapping, and expected log evidence.

---

## MOD-001: Unauthorized Coil Write

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-001 |
| **Attack Class** | Unauthorized Command |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (12/15) |

### Attack Description

An unauthorized source sends a Modbus write command (FC05 — Write Single Coil, or FC15 — Write Multiple Coils) to a PLC/RTU. Coils control physical outputs: motors, valves, pumps, relays. An unauthorized write can start/stop equipment, open/close valves, or trigger safety hazards.

### Detection Logic

```
IF protocol == "modbus"
   AND function_code IN (5, 15)
   AND source_ip NOT IN authorized_modbus_masters
THEN alert
```

### False Positives

- New engineering workstation added to the OT network but not yet added to the CDB allowlist
- Temporary contractor laptop performing legitimate maintenance
- VLAN/network reconfiguration changing source IPs

### Log Evidence (Expected)

```json
{
  "protocol": "modbus",
  "source_ip": "192.168.1.200",
  "function_code": 5,
  "reference_number": 0,
  "data": "0xFF00",
  "event_type": "request"
}
```

---

## MOD-002: Unauthorized Register Write

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-002 |
| **Attack Class** | Modify Parameter |
| **MITRE ATT&CK ICS** | [T0836 — Modify Parameter](https://attack.mitre.org/techniques/ics/T0836/) |
| **Severity** | High (12/15) |

### Attack Description

An unauthorized source writes to Modbus holding registers (FC06 — Write Single Register, or FC16 — Write Multiple Registers). Holding registers store operational parameters: set-points, thresholds, PID constants, alarm limits. Modifying these can alter process behavior without directly activating outputs.

### Detection Logic

```
IF protocol == "modbus"
   AND function_code IN (6, 16)
   AND source_ip NOT IN authorized_modbus_masters
THEN alert
```

---

## MOD-003: Rogue Master Detection

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-003 |
| **Attack Class** | Network Intrusion |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (10/15) |

### Attack Description

A Modbus master (client) that has never been seen on the network begins communicating with PLCs. This is a strong indicator of an unauthorized device connecting to the OT network — whether it's an attacker's laptop, a compromised IT device pivoting into OT, or rogue hardware.

### Detection Logic

```
IF protocol == "modbus"
   AND event_type == "first_seen_source_ip"
   AND destination_port == 502
THEN alert
```

---

## MOD-004: Illegal Function Code

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-004 |
| **Attack Class** | Protocol Fuzzing |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | Medium (8/15) |

### Attack Description

A Modbus request contains a function code outside the valid range (0, 72–119). This is almost always a fuzzing attempt, protocol exploit attempt, or misconfigured device. Valid FCs: 1–8, 11, 15–17, 20–24, 43.

### Detection Logic

```
IF protocol == "modbus"
   AND event_type == "request"
   AND function_code NOT IN (1,2,3,4,5,6,7,8,11,15,16,17,20,21,22,23,24,43)
THEN alert
```

---

## MOD-005: Mass Register Read (Reconnaissance)

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-005 |
| **Attack Class** | Reconnaissance |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Low (6/15) |

### Attack Description

A Modbus master issues an unusually high number of read commands (FC03/FC04) in a short time window, attempting to map the device's memory layout. This is the Modbus equivalent of a port scan — attackers enumerate registers to find interesting control points.

### Detection Logic

```
IF protocol == "modbus"
   AND function_code IN (3, 4)
   AND count_by_source_ip(5 minutes) > BASELINE_THRESHOLD
THEN alert
```

---

## MOD-006: Rapid Polling Detection

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-006 |
| **Attack Class** | Denial of Service |
| **MITRE ATT&CK ICS** | [T0814 — Denial of Service](https://attack.mitre.org/techniques/ics/T0814/) |
| **Severity** | Medium (8/15) |

### Attack Description

A source floods a Modbus device with requests at a rate far exceeding normal polling intervals. This can degrade PLC performance, cause watchdog timeouts, or trigger fail-safe states.

---

## MOD-007: Exception Response Flood

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-007 |
| **Attack Class** | Reconnaissance / Fuzzing |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (7/15) |

### Attack Description

High rate of Modbus exception responses (FC > 127) indicating a scanner or fuzzer is probing invalid memory addresses. Normal operations produce occasional exceptions; sustained exception floods are malicious.

---

## MOD-008: Modbus over Non-Standard Port

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MOD-008 |
| **Attack Class** | Evasion / Misconfiguration |
| **MITRE ATT&CK ICS** | [T0840 — Network Connection Enumeration](https://attack.mitre.org/techniques/ics/T0840/) |
| **Severity** | Low (4/15) |

### Attack Description

Modbus TCP traffic detected on a port other than the standard port 502. This could indicate an attacker attempting to evade detection by running Modbus on an unexpected port, or a misconfigured device that should be investigated.

### Detection Logic

```
IF protocol == "modbus"
   AND destination_port != 502
THEN alert
```

---

*Next: DNP3 Attack Catalog (Phase 2)*
