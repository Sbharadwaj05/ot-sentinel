# GNS3 Network Topology for OT Sentinel

> **Status**: Production-ready

---

## Topology Diagram

```
                         Internet (optional)
                              │
                    ┌─────────┴─────────┐
                    │   Host Machine    │
                    │  (GNS3 + Wazuh)   │
                    │   192.168.1.1     │
                    └────────┬──────────┘
                             │
                    ┌────────┴────────┐
                    │   GNS3 Cloud    │
                    │  (bridged NIC)  │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │  Virtual Switch │
                    │  192.168.1.0/24 │
                    └──┬──────┬────┬──┘
                       │      │    │
          ┌────────────┴┐  ┌──┴──┐ ┌┴────────────┐
          │   OpenPLC   │  │Wazuh│ │ Kali Linux  │
          │ 192.168.1.100│  │ .50 │ │ 192.168.1.200│
          │   :502      │  │     │ │ (Attacker)  │
          └─────────────┘  └─────┘ └─────────────┘
```

---

## Device List

| Device | IP | Ports | Purpose |
|--------|-----|-------|---------|
| OpenPLC | 192.168.1.100 | 502 | Modbus target |
| Wazuh Manager | 192.168.1.50 | 1514, 55000 | SIEM + agent comm |
| Kali Linux | 192.168.1.200 | — | Attack simulation |

---

## GNS3 Configuration

1. Create new project: `ot-sentinel-lab`
2. Add cloud node → bridge to host NIC
3. Add Ethernet switch
4. Add VMs (OpenPLC, Wazuh, Kali)
5. Connect all to switch
6. Assign static IPs

---

## Testing Multiple Protocols

| Protocol | Target Device | Port | Tools |
|----------|--------------|------|-------|
| Modbus TCP | OpenPLC | 502 | pymodbus, modbus_tap.py |
| DNP3 | (DNP3 simulator) | 20000 | dnp3_tap.py |
| IEC 104 | (IEC 104 simulator) | 2404 | iec104_tap.py |
| MQTT | Mosquitto broker | 1883 | mqtt_tap.py, paho-mqtt |
| OPC-UA | (OPC-UA server) | 4840 | opcua_tap.py |

---

*OT Sentinel — GNS3 Topology*
