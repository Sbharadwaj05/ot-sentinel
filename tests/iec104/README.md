# IEC 60870-5-104 Test Scripts

> 📋 Test scripts for IEC 104 rules (OT-SENTINEL-IEC-001 through IEC-006) are planned for v1.1.
>
> To test an IEC 104 rule now, use `wazuh-logtest` with a JSON log line:

```bash
# Test IEC-001 (Unauthorized STARTDT)
echo '{"protocol":"iec104","source_ip":"192.168.1.200","control_function":"STARTDT_act"}' | sudo /var/ossec/bin/wazuh-logtest
```

> Want to contribute? See [CONTRIBUTING.md](../../CONTRIBUTING.md) — "Write a test script for a protocol" is a good first issue.
