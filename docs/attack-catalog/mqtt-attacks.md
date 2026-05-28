# MQTT Attack Catalog

> Complete catalog of MQTT attack patterns covered by OT Sentinel.

---

## MQTT-001: Anonymous Connection

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MQTT-001 |
| **MITRE ATT&CK ICS** | [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/ics/T0855/) |
| **Severity** | Medium (8/15) |

### Attack Description
MQTT CONNECT with no username/password. Enables unauthenticated publish/subscribe to all topics — data harvest, false data injection, unauthorized control commands.

### Detection Logic
```
IF protocol == "mqtt" AND packet_type == "CONNECT"
   AND username IS null/empty AND password_flag IS false
THEN alert
```

---

## MQTT-002: Wildcard Topic Subscription

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MQTT-002 |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (9/15) |

### Attack Description
SUBSCRIBE with multi-level wildcard (#) — harvests ALL subtopics from a single subscription. Single # sub can exfiltrate data from hundreds of sensors.

### Detection Logic
```
IF protocol == "mqtt" AND packet_type == "SUBSCRIBE" AND topic contains "#"
THEN alert
```

---

## MQTT-003: Retained Message Poisoning

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MQTT-003 |
| **MITRE ATT&CK ICS** | [T0856 — Spoof Reporting Message](https://attack.mitre.org/techniques/ics/T0856/) |
| **Severity** | High (11/15) |

### Attack Description
PUBLISH with Retain=true on sensitive control topics. Retained messages persist in broker and deliver to every new subscriber — OT equivalent of "stored XSS."

### Detection Logic
```
IF protocol == "mqtt" AND packet_type == "PUBLISH"
   AND retain == true AND topic matches sensitive pattern
THEN alert
```

---

## MQTT-004: High-Frequency Publish Flood

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MQTT-004 |
| **MITRE ATT&CK ICS** | [T0814 — Denial of Service](https://attack.mitre.org/techniques/ics/T0814/) |
| **Severity** | Medium (8/15) |

### Attack Description
Abnormally high PUBLISH rate from single client — broker overload, bandwidth saturation, sensor spoofing.

### Detection Logic
```
IF protocol == "mqtt" AND packet_type == "PUBLISH"
   AND count(source_ip, 5min) > 500
THEN alert
```

---

## MQTT-005: Rogue Client (Unknown Client ID)

| Property | Value |
|----------|-------|
| **Rule ID** | OT-SENTINEL-MQTT-005 |
| **MITRE ATT&CK ICS** | [T0846 — Remote System Discovery](https://attack.mitre.org/techniques/ics/T0846/) |
| **Severity** | Medium (7/15) |

### Attack Description
CONNECT with client ID not in known clients list. Unknown client ID = rogue device or attacker.

### Detection Logic
```
IF protocol == "mqtt" AND packet_type == "CONNECT"
   AND client_id NOT IN known_mqtt_clients
THEN alert
```

---

*Next: OPC-UA Attack Catalog*
