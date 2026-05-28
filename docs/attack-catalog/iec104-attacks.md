# IEC 60870-5-104 Attack Catalog

> Complete catalog of IEC 104 attack patterns covered by OT Sentinel.

---

## IEC-001: Unauthorized STARTDT

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-001 |
| **Attack Class** | Unauthorized Session |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (12/15) |

### Attack Description

An unauthorized client sends a STARTDT activation frame to initiate data transfer with an RTU. Once STARTDT is acknowledged, the client can send I-frames containing ASDUs — including control commands. An unauthorized STARTDT is the equivalent of logging into a device without credentials.

### Detection Logic

```
IF protocol == "iec104"
   AND control_function == "STARTDT_act"
   AND source_ip NOT IN authorized_iec104_clients
THEN alert
```

---

## IEC-002: C_SC_NA Single Command Injection

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-002 |
| **Attack Class** | Unauthorized Command |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (13/15) |

### Attack Description

An unauthorized source sends a single command (ASDU type 45: C_SC_NA) to directly control a binary output — circuit breaker, valve, pump. This is the IEC 104 equivalent of Modbus FC05 (Write Single Coil).

### Detection Logic

```
IF protocol == "iec104"
   AND asdu_type_id == 45
   AND event_type == "request"
   AND source_ip NOT IN authorized_iec104_clients
THEN alert
```

---

## IEC-003: C_DC_NA Double Command Injection

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-003 |
| **Attack Class** | Unauthorized Command |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (13/15) |

### Attack Description

Unauthorized double command (ASDU type 46: C_DC_NA) targeting devices with dual-state positions — disconnectors, tap changers. Double commands provide state confirmation but are still dangerous when unauthorized.

### Detection Logic

```
IF protocol == "iec104"
   AND asdu_type_id == 46
   AND event_type == "request"
   AND source_ip NOT IN authorized_iec104_clients
THEN alert
```

---

## IEC-004: General Interrogation Abuse

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-004 |
| **Attack Class** | Reconnaissance |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (7/15) |

### Attack Description

Abnormally frequent General Interrogation requests (ASDU 100). Each GI forces the RTU to report ALL its data points. Repeated GIs map the RTU's complete IOA space — the attacker learns every control point before striking.

### Detection Logic

```
IF protocol == "iec104"
   AND asdu_type_id == 100
   AND event_type == "request"
   AND count(source_ip, 10min) > 3
THEN alert
```

---

## IEC-005: TESTFR Flooding

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-005 |
| **Attack Class** | Denial of Service |
| **MITRE ATT&CK ICS** | [T0814 — Denial of Service](https://attack.mitre.org/techniques/ics/T0814/) |
| **Severity** | Medium (8/15) |

### Attack Description

TESTFR frames at abnormally high rates — overwhelming the RTU's communication processor. Can cause session timeout, prevent legitimate I-frame transfer, or trigger buffer overflow.

### Detection Logic

```
IF protocol == "iec104"
   AND control_function matches "TESTFR_*"
   AND count(source_ip, 5min) > 200
THEN alert
```

---

## IEC-006: ASDU IOA Anomaly

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-IEC-006 |
| **Attack Class** | Data Integrity |
| **MITRE ATT&CK ICS** | [T0836 — Modify Parameter](https://attack.mitre.org/techniques/ics/T0836/) |
| **Severity** | Medium (8/15) |

### Attack Description

ASDU messages referencing IOAs not in the known list. Unknown IOAs may indicate ASDU spoofing (injecting fake data objects), probing for undocumented control points, or ASDU fuzzing.

### Detection Logic

```
IF protocol == "iec104"
   AND event_type == "request"
   AND ioa NOT IN known_iec104_ioas
THEN alert
```

---

*Next: MQTT + OPC-UA Attack Catalogs (Phase 4)*
