# IEC 60870-5-104 Protocol Primer for Detection Engineers

> **Target audience**: Detection engineers who understand Modbus/DNP3 and need IEC 104 detection patterns.
> **Prerequisites**: Modbus + DNP3 knowledge, TCP/IP fundamentals.

---

## 1. What is IEC 104?

**IEC 60870-5-104** (IEC 104) is the dominant SCADA protocol in European and Asian power grids. It's the TCP/IP transport companion to IEC 60870-5-101 (serial). If Modbus is the "HTTP of OT" and DNP3 is the "North American standard," IEC 104 is the "European/Asian standard."

Key characteristics:
- **Client-server model**: SCADA is the client, RTU/PLC is the server
- **Port 2404** (IANA registered)
- **Three APDU types**: I-frames (data), S-frames (acks), U-frames (control)
- **Information Object Addresses (IOA)**: 24-bit identifiers for every data point
- **Cause of Transmission (COT)**: 6-bit field explaining WHY data was sent
- **Session lifecycle**: Connection → STARTDT → Data Transfer → STOPDT → Disconnect

**Detection impact**: Every layer of IEC 104 provides distinct telemetry — U-frames tell you about session state, COT tells you intent, IOA tells you exactly what data point is being targeted.

---

## 2. APDU Types — The Three Frame Types

| Type | Name | Purpose | Detection Relevance |
|------|------|---------|-------------------|
| **I-frame** | Information | Carries ASDU data objects | Contains commands, measurements |
| **S-frame** | Supervisory | Acknowledges I-frames | Normal — ignore for detection |
| **U-frame** | Unnumbered | Session control | STARTDT, STOPDT, TESTFR |

---

## 3. U-Frame Control Functions

| Function | Purpose | Detection Significance |
|----------|---------|----------------------|
| **STARTDT_act** | Request data transfer | Unauthorized = attacker establishing session |
| **STARTDT_con** | Acknowledge data transfer | Normal |
| **STOPDT_act** | Stop data transfer | Unexpected = DoS or session hijack |
| **STOPDT_con** | Acknowledge stop | Normal |
| **TESTFR_act** | Keep-alive test | High frequency = DoS flooding |
| **TESTFR_con** | Keep-alive response | High frequency = DoS flooding |

**Detection rule**: Unauthorized STARTDT_act = attacker connecting. TESTFR flooding = DoS.

---

## 4. ASDU Type IDs — The Command Types

ASDU (Application Service Data Unit) is the payload carried by I-frames. The Type ID tells you exactly what kind of data is being exchanged.

### Critical ASDU Types (Control Commands)

| Type ID | Name | Detection Significance |
|---------|------|----------------------|
| **45** | C_SC_NA | Single command — circuit breaker ON/OFF |
| **46** | C_DC_NA | Double command — disconnector OPEN/CLOSE |
| **47** | C_RC_NA | Regulating step command — tap changer |
| **48** | C_SE_NA | Set-point command — change analog value |
| **49** | C_SE_NB | Set-point, scaled value |
| **50** | C_SE_NC | Set-point, float value |

### Reconnaissance ASDU Types

| Type ID | Name | Detection Significance |
|---------|------|----------------------|
| **100** | C_IC_NA | **General Interrogation** — dump ALL data |
| **101** | C_CI_NA | Counter interrogation — dump counters |
| **103** | C_CS_NA | Clock synchronization |

**Detection rule**: Type 45/46/48 from unauthorized IP = command injection. Type 100 at high frequency = recon.

---

## 5. Cause of Transmission (COT)

Every ASDU has a 6-bit COT explaining WHY this data was sent:

| COT | Name | Meaning |
|-----|------|---------|
| 1 | Periodic | Regular polling |
| 2 | Background | Background scan |
| 3 | Spontaneous | Event-driven (alarm) |
| 5 | Requested | Response to a read |
| 6 | **Activation** | **EXECUTE a command** |
| 7 | Activation confirm | Command acknowledged |
| 20 | Interrogated by GI | Response to GI request |

**Detection rule**: COT=6 (Activation) + ASDU=45/46 from unknown IP = unauthorized control.

---

## 6. Normal vs. Malicious Traffic

### Normal IEC 104 Traffic

```
SCADA (192.168.1.10) → RTU (192.168.1.100:2404):
  - STARTDT_act (once per connection)
  - I-frames with Type 1 (M_SP_NA) every 1-5 sec (cyclic polling)
  - S-frames acknowledging received I-frames
  - TESTFR_act every 10-30 sec (keep-alive)
  - GI requests: VERY rare (once at connection start)
  - Commands (Type 45/46): VERY rare (operator action only)
```

### Attack Traffic

```
Attacker (192.168.1.200) → RTU (192.168.1.100:2404):
  - STARTDT_act from unknown IP
  - Type 45 (C_SC_NA) with IOA for critical breaker
  - Type 100 (GI) repeated 5x in 2 minutes — recon
  - TESTFR flooding 300x per minute — DoS
  - Type 45/46 with COT=6 (Activation) — execute command
```

---

## 7. OT Sentinel's IEC 104 Rule Strategy

| Rule ID | Attack Pattern | Detection Logic |
|---------|---------------|-----------------|
| IEC-001 | Unauthorized STARTDT | STARTDT_act + source IP NOT in CDB |
| IEC-002 | C_SC_NA Single Command Injection | ASDU 45 + source IP NOT in CDB |
| IEC-003 | C_DC_NA Double Command Injection | ASDU 46 + source IP NOT in CDB |
| IEC-004 | General Interrogation Abuse | ASDU 100 frequency > 3/10min |
| IEC-005 | TESTFR Flooding | TESTFR frequency > 200/5min |
| IEC-006 | ASDU IOA Anomaly | IOA NOT in known IOA CDB list |

---

## 8. References

- [IEC 60870-5-104 Standard](https://webstore.iec.ch/publication/3747)
- [MITRE ATT&CK for ICS — T0855](https://attack.mitre.org/techniques/ics/T0855/)
- [MITRE ATT&CK for ICS — T0814](https://attack.mitre.org/techniques/ics/T0814/)

---

*OT Sentinel — Phase 3: IEC 60870-5-104 Detection Rules*
