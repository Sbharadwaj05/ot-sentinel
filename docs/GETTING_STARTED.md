# Getting Started with OT Sentinel

> **You don't need to be an OT engineer to use this.** If you know Wazuh, Sigma, or
> any SIEM, you're 80% there. This guide bridges the last 20%.

---

## What You're Looking At

You just found a repo full of detection rules for industrial protocols. Here's what
that actually means for you:

| If you're a... | Use this to... |
|----------------|----------------|
| **SOC Analyst** | Deploy rules to Wazuh, get alerts when someone touches your PLCs |
| **Detection Engineer** | Fork rules as templates, write new ones for your protocols |
| **Penetration Tester** | Understand what OT attacks look like in logs (defensive context) |
| **Security Engineer** | Add OT visibility to your existing SIEM for zero extra cost |
| **Student** | Learn how OT protocols work through the lens of security detection |

---

## Step 1: Understand What You're Protecting

Industrial protocols control physical things — pumps, valves, breakers, motors.
They were designed in the 1970s-1990s when "security" meant a locked door.
Almost none of them have authentication built in.

| Protocol | What it controls | Standard port | Authentication? |
|----------|-----------------|---------------|-----------------|
| Modbus TCP | PLCs, RTUs — pumps, motors, valves | 502 | No |
| DNP3 | Electric substations, water treatment | 20000 | Optional (rarely enabled) |
| IEC 104 | European/Asian power grids | 2404 | No |
| MQTT | IIoT sensors, building automation | 1883 | Optional (often disabled) |
| OPC-UA | Modern factory automation | 4840 | Yes (often misconfigured) |

**The key insight**: If you can reach these devices on the network, you can
probably control them. Detection rules are your compensating control.

---

## Step 2: Read ONE Protocol Primer

Choose the protocol relevant to you. Each primer is written for security people,
not OT engineers:

- [Modbus Primer](protocol-guides/modbus-primer.md) ← **Start here**
- [DNP3 Primer](protocol-guides/dnp3-primer.md)
- [IEC 104 Primer](protocol-guides/iec104-primer.md)
- [MQTT Primer](protocol-guides/mqtt-primer.md)
- [OPC-UA Primer](protocol-guides/opcua-primer.md)

Each primer tells you:
1. What the protocol does (in security terms)
2. What normal traffic looks like
3. What attack traffic looks like
4. Which fields to monitor
5. Wireshark filters for analysis

---

## Step 3: Deploy to Wazuh (~10 minutes)

```bash
git clone https://github.com/Sbharadwaj05/ot-sentinel.git
cd ot-sentinel

# Copy ALL decoders
sudo cp rules/wazuh/decoders/*.xml /var/ossec/etc/decoders/

# Copy rules for a specific protocol (example: Modbus)
sudo cp rules/wazuh/modbus/*.xml /var/ossec/etc/rules/

# Copy CDB allowlists
sudo cp cdb-lists/authorized_modbus_masters /var/ossec/etc/lists/

# Add to ossec.conf <ossec_config>:
#   <list>etc/lists/authorized_modbus_masters</list>

sudo systemctl restart wazuh-manager
```

---

## Step 4: Generate a Test Alert

```bash
# Feed a simulated attack log to Wazuh
echo '{"protocol":"modbus","source_ip":"192.168.1.200","function_code":5,"event_type":"request"}' \
  | /var/ossec/bin/wazuh-logtest
```

You should see:
```
**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
**Phase 3: Completed filtering (rules).
   Rule id: 200001
   Rule level: 12
   Description: OT Sentinel: Unauthorized Modbus coil write detected.
```

---

## Step 5: Understand What Just Happened

| Field | Meaning |
|-------|---------|
| `protocol: modbus` | The decoder identified Modbus traffic |
| `function_code: 5` | Write Single Coil — a control command |
| `event_type: request` | Someone sent this TO the PLC |
| `source_ip: 192.168.1.200` | The attacker's IP |

OT Sentinel rule 200001 matched because:
1. The protocol is Modbus
2. Someone tried to write to a coil (control action)
3. The source IP is not in the `authorized_modbus_masters` allowlist

---

## Step 6: Read One Attack Catalog

- [Modbus Attacks](attack-catalog/modbus-attacks.md)
- [DNP3 Attacks](attack-catalog/dnp3-attacks.md)
- [IEC 104 Attacks](attack-catalog/iec104-attacks.md)
- [MQTT Attacks](attack-catalog/mqtt-attacks.md)
- [OPC-UA Attacks](attack-catalog/opc-ua-attacks.md)

Each catalog entry tells you:
1. What the attack does
2. The exact detection logic
3. What log evidence it produces
4. False positive scenarios to watch for

---

## Common Questions

### "Do I need an actual PLC to test this?"

**No.** The test scripts work in two modes:
1. Real PLC mode (if you have OpenPLC running)
2. Simulated mode (generates JSON log lines without hardware)

### "What's a CDB list?"

It's Wazuh's version of an allowlist. A text file with `IP:Description` entries.
Rules check if a field value (like source IP) exists in the list. If it doesn't
exist → alert fires.

### "Can I use these with Splunk / Elastic / other SIEMs?"

The **Sigma rules** are SIEM-agnostic. Use `sigmac` to convert them to your
platform's format:
```bash
pip install sigmatools
sigmac -t splunk rules/sigma/modbus/*.yml
```

### "Which protocol should I monitor first?"

Modbus. It's everywhere, it's simple, and it has zero built-in security.
If you find Modbus on your network, you need these rules.

---

## Next Steps

1. [ ] Read one protocol primer (10 min)
2. [ ] Deploy to Wazuh (10 min)
3. [ ] Generate a test alert (2 min)
4. [ ] Read one attack catalog (15 min)
5. [ ] Deploy to production (tune allowlists first!)
6. [ ] Run the full [Lab Testing Guide](lab-setup/testing-guide.md)

---

*Still lost? Open an issue with the `question` tag. OT security is hard —
nobody expects you to get it in one sitting.*
