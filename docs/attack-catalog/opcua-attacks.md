# OPC-UA Attack Catalog

> Complete catalog of OPC-UA attack patterns covered by OT Sentinel.

---

## OPC-001: Session Hijacking

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-OPC-001 |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | High (12/15) |

### Attack Description
OPC-UA ActivateSession with stolen authentication token from unexpected IP. Attacker steals valid session token and hijacks an active session to issue unauthorized reads, writes, or method calls.

### Detection Logic
```
IF protocol == "opcua" AND service_type == "ActivateSession"
THEN alert (monitor for unexpected IP associations)
```

---

## OPC-002: Node Enumeration (Reconnaissance)

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-OPC-002 |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (7/15) |

### Attack Description
Abnormally high frequency of OPC-UA Browse requests — attacker mapping the server's node tree to discover data points, control objects, and methods.

### Detection Logic
```
IF protocol == "opcua" AND service_type == "Browse"
   AND count(source_ip, 5min) > 100
THEN alert
```

---

## OPC-003: Unauthorized Node Write

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-OPC-003 |
| **MITRE ATT&CK ICS** | [T0836 — Modify Parameter](https://attack.mitre.org/techniques/ics/T0836/) |
| **Severity** | High (13/15) |

### Attack Description
OPC-UA Write from unauthorized source IP. Can modify variable values (set-points, thresholds), invoke methods (trigger controls), and alter event filters.

### Detection Logic
```
IF protocol == "opcua" AND service_type == "Write"
   AND source_ip NOT IN authorized_opcua_clients
THEN alert
```

---

*End of attack catalog — all 5 protocols covered*
