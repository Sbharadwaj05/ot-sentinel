# Wazuh Configuration for OT Sentinel

> **Status**: Production-ready

---

## Agent Configuration (`ossec.conf`)

Add to the Wazuh agent monitoring the OT network:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/modbus/modbus_tap.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/dnp3/dnp3_tap.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/iec104/iec104_tap.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/mqtt/mqtt_tap.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/opcua/opcua_tap.log</location>
  </localfile>
</ossec_config>
```

---

## Manager Deployment

```bash
# Copy decoders
sudo cp rules/wazuh/decoders/*.xml /var/ossec/etc/decoders/

# Copy rules
sudo cp rules/wazuh/modbus/*.xml /var/ossec/etc/rules/
sudo cp rules/wazuh/dnp3/*.xml /var/ossec/etc/rules/
sudo cp rules/wazuh/iec104/*.xml /var/ossec/etc/rules/
sudo cp rules/wazuh/mqtt/*.xml /var/ossec/etc/rules/
sudo cp rules/wazuh/opc-ua/*.xml /var/ossec/etc/rules/

# Copy CDB lists
sudo cp cdb-lists/* /var/ossec/etc/lists/

# Add lists to ossec.conf
# <list>etc/lists/authorized_modbus_masters</list>
# <list>etc/lists/known_modbus_masters</list>
# ... (repeat for all CDB lists)

# Restart
sudo systemctl restart wazuh-manager
```

---

## Verification

```bash
# Test a Modbus log
echo '{"protocol":"modbus","source_ip":"192.168.1.200","function_code":5,"event_type":"request"}' \
  | /var/ossec/bin/wazuh-logtest

# Check for OT Sentinel alerts
grep "ot-sentinel" /var/ossec/logs/alerts/alerts.json | tail -20
```

---

*OT Sentinel — Wazuh Configuration Guide*
