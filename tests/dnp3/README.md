# DNP3 Test Scripts

> 📋 Test scripts for DNP3 rules (OT-SENTINEL-DNP-001 through DNP-007) are planned for v1.1.
>
> To test a DNP3 rule now, use `wazuh-logtest` with a JSON log line:

```bash
# Test DNP-001 (Rogue Outstation)
echo '{"protocol":"dnp3","source_ip":"192.168.1.200","function_code":130,"event_type":"response","data_link_source":99}' | sudo /var/ossec/bin/wazuh-logtest
```

> Want to contribute? See [CONTRIBUTING.md](../../CONTRIBUTING.md) — "Write a test script for DNP3 rule" is a good first issue.
