# OpenPLC Setup Guide for OT Sentinel Testing

> **Status**: Production-ready
> **Target**: OpenPLC v3 on Ubuntu 22.04 LTS

---

## Overview

OpenPLC is an open-source PLC runtime that supports Modbus TCP on port 502. It's the primary target for Phase 1 (Modbus) OT Sentinel rule testing.

---

## Installation

```bash
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3
./install.sh linux
```

Post-install:
```bash
sudo ./start_openplc.sh
# Access web interface at: https://localhost:8080
# Default credentials: openplc / openplc
```

---

## Test Ladder Logic Program

Upload this minimal program to expose Modbus coils and registers for testing:

1. In OpenPLC web interface → Programs → Upload
2. Create a program with:
   - 8 coils at %QX0.0 – %QX0.7
   - 4 holding registers at %QW0 – %QW3
   - 4 input registers at %IW0 – %IW3

---

## Modbus Configuration

In OpenPLC web interface → Slave Devices:
- Enable Modbus TCP
- Port: 502
- Disable "Write Protection" for testing

---

## Testing OT Sentinel Rules

```bash
# Test MOD-001: Unauthorized coil write
python tests/modbus/test_unauthorized_write.py --target 192.168.1.100

# Generate demo traffic
python tools/modbus_tap.py --demo --target 192.168.1.100

# Feed to Wazuh
python tools/modbus_tap.py --demo --target 192.168.1.100 >> /var/ossec/logs/modbus/modbus_tap.log
```

---

## Expected Alerts

After running the test script, check Wazuh for:
- Rule 200001: "OT Sentinel: Unauthorized Modbus coil write detected" (Level 12)
- Source IP should NOT be in authorized_modbus_masters CDB list

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.id=="200001")'
```

---

*OT Sentinel — Lab Setup Guide*
