# MQTT Protocol Primer for Detection Engineers

> **Target audience**: Detection engineers new to MQTT in OT/ICS contexts.
> **Prerequisites**: Basic TCP/IP, pub/sub concepts.

---

## 1. What is MQTT?

**Message Queuing Telemetry Transport** (MQTT) is a lightweight publish/subscribe messaging protocol designed for constrained devices and low-bandwidth networks. While originally built for oil pipeline SCADA in 1999, it's now widely used in:
- IIoT sensor networks (temperature, vibration, pressure)
- Building automation (HVAC, lighting, access control)
- Smart grid telemetry
- OT/IT data bridges (historians, dashboards)

**Key property for detection**: MQTT is broker-mediated — all traffic flows through a central broker. This single choke point is your detection sweet spot. Monitor the broker, and you monitor everything.

---

## 2. Architecture

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Sensor  │────▶│          │◀────│  SCADA   │
│ (publish)│     │  BROKER  │     │(subscribe)│
└──────────┘     │  :1883   │     └──────────┘
                 └──────────┘
                       ▲
                 ┌──────────┐
                 │ Attacker │
                 │(pub+sub) │
                 └──────────┘
```

---

## 3. Topic Structure

MQTT topics are hierarchical strings separated by `/`:

```
sensors/temperature/zone1
control/pump/station3/cmd
alarm/critical/overflow
```

**Wildcards**:
- `+` — single level: `sensors/+/temperature` matches zone1, zone2, zone3
- `#` — multi level: `sensors/#` matches EVERYTHING under sensors/

---

## 4. Packet Types — Detection Cheat Sheet

| Packet | Direction | Detection Use |
|--------|-----------|---------------|
| **CONNECT** | Client→Broker | Check credentials, client ID |
| **PUBLISH** | Bidirectional | Check topic, retain flag, QoS |
| **SUBSCRIBE** | Client→Broker | Check topic for wildcards |
| **DISCONNECT** | Client→Broker | Session termination |

---

## 5. OT Sentinel's MQTT Rule Strategy

| Rule | Attack | Detection |
|------|--------|-----------|
| MQTT-001 | Anonymous Connect | CONNECT with null username + no password |
| MQTT-002 | Wildcard Subscription | SUBSCRIBE topic contains # |
| MQTT-003 | Retained Poisoning | PUBLISH with retain=true on control topics |
| MQTT-004 | Publish Flood | PUBLISH rate > 500/5min per client |
| MQTT-005 | Rogue Client | CONNECT with unknown client ID |

---

*OT Sentinel — Phase 4: MQTT Detection Rules*
