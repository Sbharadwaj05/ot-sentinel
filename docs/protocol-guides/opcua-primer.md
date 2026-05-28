# OPC-UA Protocol Primer for Detection Engineers

> **Target audience**: Detection engineers new to OPC-UA in OT/ICS contexts.
> **Prerequisites**: Basic understanding of industrial automation.

---

## 1. What is OPC-UA?

**OPC Unified Architecture** (OPC-UA) is the modern, secure replacement for classic OPC (OLE for Process Control). It's platform-independent, supports encryption and authentication, and is the standard for Industry 4.0 communication.

**Key property for detection**: OPC-UA has built-in security (unlike Modbus), but misconfiguration is rampant. Many deployments run with SecurityPolicy=None (no encryption, no auth).

---

## 2. Service Types — Detection Cheat Sheet

| Service | Purpose | Detection |
|---------|---------|-----------|
| **CreateSession** | Establish new session | Monitor for unexpected clients |
| **ActivateSession** | Activate session with token | Hijacking indicator |
| **Browse** | Discover node tree | Mass Browse = recon |
| **Read** | Read node values | Normal |
| **Write** | Modify node values | **CRITICAL — unauthorized = attack** |
| **Call** | Invoke methods | Can trigger physical actions |
| **CloseSession** | Terminate session | Normal |

---

## 3. Node ID Format

OPC-UA nodes are identified by namespace-qualified strings:

```
ns=1;s=Temperature
ns=2;i=1001
```

---

## 4. Security Policies

| Policy | Encryption | Auth | Detection |
|--------|-----------|------|-----------|
| **None** | No | No | CRITICAL — monitor for this |
| Basic128Rsa15 | Yes | Yes | Deprecated |
| Basic256 | Yes | Yes | Legacy |
| **Basic256Sha256** | Yes | Yes | Minimum acceptable |

---

## 5. OT Sentinel's OPC-UA Rule Strategy

| Rule | Attack | Detection |
|------|--------|-----------|
| OPC-001 | Session Hijacking | ActivateSession from unauthorized IP |
| OPC-002 | Node Enumeration | Browse rate > 100/5min per client |
| OPC-003 | Unauthorized Write | Write from unauthorized IP |

---

*OT Sentinel — Phase 4: OPC-UA Detection Rules*
