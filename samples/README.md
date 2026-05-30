# Sample Logs

> Drop these JSON log lines into `wazuh-logtest` to see OT Sentinel rules fire — no hardware needed.

---

## Modbus

### Unauthorized Coil Write (MOD-001)

```bash
cat samples/modbus_coil_write.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200001, Level 12

### Unauthorized Register Write (MOD-002)

```bash
cat samples/modbus_register_write.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200002, Level 12

### Illegal Function Code (MOD-004)

```bash
cat samples/modbus_illegal_fc.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200004, Level 8

---

## DNP3

### Rogue Outstation (DNP-001)

```bash
cat samples/dnp3_rogue_outstation.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200012, Level 12

---

## IEC 104

### Unauthorized STARTDT (IEC-001)

```bash
cat samples/iec104_unauthorized_startdt.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200022, Level 12

---

## MQTT

### Anonymous Connection (MQT-001)

```bash
cat samples/mqtt_anonymous_connect.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200030, Level 8

---

## OPC-UA

### Unauthorized Write (OPC-003)

```bash
cat samples/opcua_unauthorized_write.json | sudo /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200039, Level 13

---

## Batch Test All Protocols

```bash
for f in samples/*.json; do
  echo "=== $(basename $f) ==="
  cat "$f" | sudo /var/ossec/bin/wazuh-logtest 2>&1 | grep "id:\|level:\|description:" | head -3
  echo ""
done
```

---

*These samples are validated against Wazuh 4.14.5 + OT Sentinel v1.0 rules.*
