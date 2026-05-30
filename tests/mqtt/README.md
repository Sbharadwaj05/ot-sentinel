# MQTT Test Scripts

> 📋 Test scripts for MQTT rules (OT-SENTINEL-MQTT-001 through MQTT-005) are planned for v1.1.
>
> To test an MQTT rule now, use `wazuh-logtest` with a JSON log line:

```bash
# Test MQTT-001 (Anonymous Connect)
echo '{"protocol":"mqtt","source_ip":"192.168.1.200","packet_type":"CONNECT","client_id":"rogue","username":null,"password_flag":false,"event_type":"request"}' | sudo /var/ossec/bin/wazuh-logtest
```

> Want to contribute? See [CONTRIBUTING.md](../../CONTRIBUTING.md).
