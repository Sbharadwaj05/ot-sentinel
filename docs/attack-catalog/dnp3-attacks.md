# DNP3 Attack Catalog

> Complete catalog of DNP3 attack patterns covered by OT Sentinel detection rules.

---

## DNP-001: Unsolicited Response from Rogue Outstation

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-001 |
| **Attack Class** | Spoof Reporting |
| **MITRE ATT&CK ICS** | [T0856 — Spoof Reporting Message](https://attack.mitre.org/techniques/ics/T0856/) |
| **Severity** | High (12/15) |

### Attack Description

A rogue device sends forged DNP3 unsolicited response messages (FC 0x82) claiming to be a legitimate outstation. The attacker injects false telemetry — fake sensor readings, false alarm states, incorrect breaker positions. Operators make decisions based on falsified data.

### Detection Logic

```
IF protocol == "dnp3"
   AND function_code IN (82, 130)
   AND event_type == "response"
   AND data_link_source NOT IN known_dnp3_outstations
THEN alert
```

---

## DNP-002: Direct Operate without Authorization

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-002 |
| **Attack Class** | Unauthorized Command |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (13/15) |

### Attack Description

An unauthorized source sends DNP3 Direct Operate commands (FC 0x05/0x06) to control physical outputs without the select-before-operate safety check. Controls CROB objects: circuit breakers, valves, pumps, protective relays.

### Detection Logic

```
IF protocol == "dnp3"
   AND function_code IN (5, 6)
   AND event_type == "request"
   AND source_ip NOT IN authorized_dnp3_masters
THEN alert
```

---

## DNP-003: Broadcast Command Abuse

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-003 |
| **Attack Class** | Unauthorized Command |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | Medium (10/15) |

### Attack Description

DNP3 commands sent to broadcast address 0xFFFF (65535) or reserved addresses 65520-65534. These affect ALL devices on the network simultaneously. Can cold restart every outstation, disable all unsolicited reporting, or issue mass control operations.

### Detection Logic

```
IF protocol == "dnp3"
   AND event_type == "request"
   AND data_link_destination >= 65520
THEN alert
```

---

## DNP-004: Authentication Failure Spike

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-004 |
| **Attack Class** | Authentication Bypass |
| **MITRE ATT&CK ICS** | [T0858 — Spoof Reporting Message](https://attack.mitre.org/techniques/ics/T0858/) |
| **Severity** | Medium (9/15) |

### Attack Description

Abnormally high frequency of DNP3 SA messages (FC 0x20/0x83) — indicates brute-force, challenge replay, or SA bypass attempts. SA exchanges should be rare (session initiation only).

### Detection Logic

```
IF protocol == "dnp3"
   AND function_code IN (32, 131)
   AND count(source_ip, 5min) > 10
THEN alert
```

---

## DNP-005: Sequence Number Regression (Replay)

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-005 |
| **Attack Class** | Replay Attack |
| **MITRE ATT&CK ICS** | [T0856 — Spoof Reporting Message](https://attack.mitre.org/techniques/ics/T0856/) |
| **Severity** | Medium (8/15) |

### Attack Description

Repeated DNP3 messages with abnormally low sequence numbers (0-2) — replay tools restart counters when retransmitting captured traffic. Each 0-2 cycle = one replay attempt.

**Limitation**: This is an imperfect heuristic. True replay detection requires stateful sequence number tracking per connection. This rule detects the most common replay pattern.

### Detection Logic

```
IF protocol == "dnp3"
   AND event_type == "request"
   AND sequence_number <= 2
   AND count(source_ip, 5min) > 3
THEN alert
```

---

## DNP-006: Unknown Data Link Address

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-006 |
| **Attack Class** | Network Discovery |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Low (5/15) |

### Attack Description

DNP3 traffic from/to data link addresses not in the known device list. Indicates a new or rogue device on the network, or network scanning activity.

### Detection Logic

```
IF protocol == "dnp3"
   AND event_type == "request"
   AND data_link_source NOT IN known_dnp3_addresses
THEN alert
```

---

## DNP-007: Mass Data Read (Reconnaissance)

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-DNP-007 |
| **Attack Class** | Reconnaissance |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Low (6/15) |

### Attack Description

Unusually high volume of DNP3 Read requests (FC 0x01) — device enumeration. Attacker maps data points (binary inputs, analog inputs, counters) to identify control targets.

### Detection Logic

```
IF protocol == "dnp3"
   AND function_code == 1
   AND event_type == "request"
   AND count(source_ip, 5min) > 100
THEN alert
```

---

*Next: IEC 60870-5-104 Attack Catalog (Phase 3)*
