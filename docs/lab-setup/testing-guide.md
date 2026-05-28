# OT Sentinel — Lab Testing Guide

## Quick Start

```bash
# Spin up OpenPLC VM, deploy rules to Wazuh, run all 8 tests:

sudo cp rules/wazuh/decoders/modbus_decoder.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/modbus/*.xml /var/ossec/etc/rules/
sudo cp cdb-lists/authorized_modbus_masters /var/ossec/etc/lists/
sudo cp cdb-lists/known_modbus_masters /var/ossec/etc/lists/
sudo systemctl restart wazuh-manager

cd tests/modbus/
python test_unauthorized_write.py --target 192.168.56.10
python test_unauthorized_register_write.py --target 192.168.56.10
python test_rogue_master.py --target 192.168.56.10
python test_illegal_function.py --target 192.168.56.10
python test_mass_read.py --target 192.168.56.10 --count 60
python test_rapid_polling.py --target 192.168.56.10 --count 250
python test_exception_flood.py --target 192.168.56.10 --count 40
python test_nonstandard_port.py --target 192.168.56.10 --port 1502

grep "200001\|200002\|200003\|200004\|200006\|200008\|200010\|200011" /var/ossec/logs/alerts/alerts.json
```

---

> **Goal**: Validate all rules against a real OpenPLC + GNS3 digital twin lab.
> **Time**: ~4-6 hours for full Tier 1 + Tier 2
> **Prerequisites**: 16GB RAM, VirtualBox/VMware, Ubuntu 22.04 ISO

---

## Lab Architecture

```
┌──────────────────────────────────────────────────┐
│              Host Machine (Your PC)               │
│                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │  OpenPLC VM  │  │  Kali VM     │  │  Wazuh   │ │
│  │ 192.168.56.10│  │192.168.56.20 │  │  Manager │ │
│  │   :502       │  │  (attacker)  │  │  :55000  │ │
│  └──────┬───────┘  └──────┬───────┘  └────┬─────┘ │
│         │                 │                │       │
│         └────────┬────────┴────────────────┘       │
│                  │                                  │
│          ┌───────┴───────┐                          │
│          │  Host-Only    │                          │
│          │  Network      │                          │
│          │ 192.168.56.0/24│                         │
│          └───────────────┘                          │
└──────────────────────────────────────────────────┘
```

**Why host-only instead of GNS3 for Tier 1**: Faster setup. OpenPLC runs in a VM.
GNS3 adds complexity you don't need for Modbus testing. Add GNS3 later for
multi-protocol testing.

---

## Step 1: Set Up OpenPLC VM (~30 min)

### 1.1 Create the VM

```bash
# Download Ubuntu Server 22.04 LTS ISO
# Create VM in VirtualBox:
#   - Name: OpenPLC
#   - RAM: 2048 MB
#   - Disk: 20 GB
#   - Network: Host-Only Adapter (vboxnet0)
```

### 1.2 Install OpenPLC

```bash
# Inside the VM after Ubuntu install:
sudo apt update && sudo apt upgrade -y
sudo apt install -y git build-essential

git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3
./install.sh linux

# Start OpenPLC
sudo ./start_openplc.sh

# Note the IP (should be 192.168.56.10 if host-only)
ip addr show | grep 192.168
```

### 1.3 Configure OpenPLC for Modbus Testing

1. Open browser → `https://192.168.56.10:8080`
2. Login: `openplc` / `openplc`
3. Go to **Slave Devices** → enable Modbus TCP on port 502
4. **Disable Write Protection** (needed for write tests)
5. Upload a simple program or use the default blank program (has default coils/registers)

### 1.4 Verify Modbus is reachable

From your host machine:
```bash
pip install pymodbus
python -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('192.168.56.10', port=502)
c.connect()
result = c.read_coils(0, 8)
print('Coils:', result.bits)
c.close()
"
```

---

## Step 2: Set Up Wazuh (~20 min)

### 2.1 Install Wazuh Manager

```bash
# On the same host or a separate VM
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo WAZUH_MANAGER="YOUR_IP" bash wazuh-install.sh --wazuh-server wazuh-server
# Note the admin password from the output
```

### 2.2 Deploy OT Sentinel Rules

```bash
cd ot-sentinel/

# Copy decoders
sudo cp rules/wazuh/decoders/modbus_decoder.xml /var/ossec/etc/decoders/

# Copy Modbus rules
sudo cp rules/wazuh/modbus/*.xml /var/ossec/etc/rules/

# Copy CDB lists
sudo cp cdb-lists/authorized_modbus_masters /var/ossec/etc/lists/
sudo cp cdb-lists/known_modbus_masters /var/ossec/etc/lists/
sudo cp cdb-lists/non_standard_modbus_ports /var/ossec/etc/lists/

# Register CDB lists in ossec.conf (add these inside <ossec_config>):
sudo nano /var/ossec/etc/ossec.conf
```

Add to `<ossec_config>`:
```xml
<ruleset>
  <list>etc/lists/authorized_modbus_masters</list>
  <list>etc/lists/known_modbus_masters</list>
  <list>etc/lists/non_standard_modbus_ports</list>
</ruleset>
```

Restart:
```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '.'
```

---

## Step 3: Run modbus_tap.py (Traffic Generator)

The traffic tap outputs JSON logs that Wazuh ingests:

```bash
# Option A: Generate demo traffic (no real PLC needed)
python tools/modbus_tap.py --demo --target 192.168.56.10 --port 502

# Option B: Pipe to Wazuh agent log file
python tools/modbus_tap.py --demo --target 192.168.56.10 --port 502 \
  >> /var/ossec/logs/modbus/modbus_tap.log
```

Each line looks like:
```json
{"protocol":"modbus","source_ip":"192.168.1.10","function_code":3,"event_type":"request",...}
```

---

## Step 4: Tier 1 — Test All 8 Modbus Rules (~2-3 hours)

### Prerequisites

```bash
pip install pymodbus
cd ot-sentinel/tests/modbus/
```

### MOD-001: Unauthorized Coil Write

```bash
python test_unauthorized_write.py --target 192.168.56.10 --port 502
```

**Expected alert**:
- Rule ID: 200001
- Level: 12
- Description: "OT Sentinel: Unauthorized Modbus coil write detected"
- Source IP: YOUR machine's IP (should NOT be in authorized_modbus_masters)

**Verify**: `grep "200001" /var/ossec/logs/alerts/alerts.json | tail -1 | jq '.'`

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-002: Unauthorized Register Write

```bash
python test_unauthorized_register_write.py --target 192.168.56.10 --port 502
```

**Expected alert**: Rule 200002, Level 12, "Unauthorized Modbus register write"

**Verify**: `grep "200002" /var/ossec/logs/alerts/alerts.json | tail -1`

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-003: Rogue Master Detection

```bash
python test_rogue_master.py --target 192.168.56.10 --port 502
```

**Expected alert**: Rule 200003, Level 10, "Rogue Modbus master detected"

**Note**: Make sure your source IP is NOT in `cdb-lists/known_modbus_masters`.

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-004: Illegal Function Code

```bash
python test_illegal_function.py --target 192.168.56.10 --port 502
```

**Expected alert**: Rule 200004, Level 8, "Illegal Modbus function code detected"

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-005: Mass Register Read (Reconnaissance)

```bash
python test_mass_read.py --target 192.168.56.10 --port 502 --count 60
```

**Expected alert**: Rule 200006, Level 6, "Mass Modbus register read detected"

**Note**: Sends 60 FC03 reads in rapid succession. Needs the parent tracker (200005)
to fire at 50 in 5 min. The test sends 60 to guarantee crossing the threshold.

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-006: Rapid Polling (DoS)

```bash
python test_rapid_polling.py --target 192.168.56.10 --port 502 --count 250
```

**Expected alert**: Rule 200008, Level 8, "Rapid Modbus polling detected"

**Note**: Sends 250 requests rapidly. Threshold is 200 in 5 min.

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-007: Exception Response Flood

```bash
python test_exception_flood.py --target 192.168.56.10 --port 502 --count 40
```

**Expected alert**: Rule 200010, Level 7, "Modbus exception response flood"

**Note**: Sends reads to invalid register addresses to trigger exception responses.

**Result**: ☐ PASS / ☐ FAIL

---

### MOD-008: Non-Standard Port

```bash
python test_nonstandard_port.py --target 192.168.56.10 --port 1502
```

**Expected alert**: Rule 200011, Level 4, "Modbus traffic detected on non-standard port"

**Note**: Connects on port 1502 instead of 502. Make sure OpenPLC isn't actually
listening on 1502 — we just want the log line, not a real connection.

**Result**: ☐ PASS / ☐ FAIL

---

## Step 5: Tier 2 — Test 1 Rule Per Protocol (~2-3 hours)

### 5.1 DNP3

Use a DNP3 simulator or the test script:

```bash
# Deploy DNP3 decoder + rules
sudo cp rules/wazuh/decoders/dnp3_decoder.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/dnp3/*.xml /var/ossec/etc/rules/
sudo cp cdb-lists/known_dnp3_outstations /var/ossec/etc/lists/
sudo cp cdb-lists/known_dnp3_addresses /var/ossec/etc/lists/
sudo cp cdb-lists/authorized_dnp3_masters /var/ossec/etc/lists/
sudo systemctl restart wazuh-manager

# Test DNP-001 (Rogue Outstation) — inject a fake unsolicited response log
echo '{"protocol":"dnp3","source_ip":"192.168.56.20","destination_ip":"192.168.56.10","destination_port":20000,"data_link_source":99,"data_link_destination":200,"function_code":130,"function_name":"unsolicited_response","event_type":"response"}' | /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200012, Level 12, outstation address 99 NOT in known list

**Result**: ☐ PASS / ☐ FAIL

---

### 5.2 IEC 60870-5-104

```bash
# Deploy decoder + rules
sudo cp rules/wazuh/decoders/iec104_decoder.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/iec104/*.xml /var/ossec/etc/rules/
sudo cp cdb-lists/authorized_iec104_clients /var/ossec/etc/lists/
sudo systemctl restart wazuh-manager

# Test IEC-001 (Unauthorized STARTDT) — inject log line
echo '{"protocol":"iec104","source_ip":"192.168.56.20","destination_ip":"192.168.56.10","destination_port":2404,"apdu_type":"U","control_function":"STARTDT_act","event_type":"request"}' | /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200022, Level 12, unauthorized STARTDT

**Result**: ☐ PASS / ☐ FAIL

---

### 5.3 MQTT

```bash
# Deploy decoder + rules
sudo cp rules/wazuh/decoders/mqtt_decoder.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/mqtt/*.xml /var/ossec/etc/rules/
sudo cp cdb-lists/known_mqtt_clients /var/ossec/etc/lists/
sudo systemctl restart wazuh-manager

# Test MQTT-001 (Anonymous Connection)
echo '{"protocol":"mqtt","source_ip":"192.168.56.20","destination_ip":"192.168.56.10","destination_port":1883,"packet_type":"CONNECT","client_id":"rogue_device","username":null,"password_flag":false,"event_type":"request"}' | /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200030, Level 8, anonymous MQTT connect

**Result**: ☐ PASS / ☐ FAIL

---

### 5.4 OPC-UA

```bash
# Deploy decoder + rules
sudo cp rules/wazuh/decoders/opcua_decoder.xml /var/ossec/etc/decoders/
sudo cp rules/wazuh/opc-ua/*.xml /var/ossec/etc/rules/
sudo cp cdb-lists/authorized_opcua_clients /var/ossec/etc/lists/
sudo systemctl restart wazuh-manager

# Test OPC-003 (Unauthorized Write)
echo '{"protocol":"opcua","source_ip":"192.168.56.20","destination_ip":"192.168.56.10","destination_port":4840,"service_type":"Write","node_id":"ns=1;s=Temperature","event_type":"request"}' | /var/ossec/bin/wazuh-logtest
```

**Expected**: Rule 200039, Level 13, unauthorized OPC-UA Write

**Result**: ☐ PASS / ☐ FAIL

---

## Step 6: After Testing — Update the Rules

For every rule that passes, update the header:

```xml
<!--
  Rule: OT-SENTINEL-MOD-001
  ...
  Tested: Yes (OpenPLC + GNS3, 2026-06-01)
-->
```

And update the Sigma rule:
```yaml
status: stable  # changed from "experimental" to "stable" after testing
```

---

## Step 7: Victory Checklist

| Protocol | Rules Tested | Pass | Fail | Signed Off |
|----------|-------------|------|------|------------|
| Modbus | 8/8 | ☐ | ☐ | ☐ |
| DNP3 | 1/7 | ☐ | ☐ | ☐ |
| IEC 104 | 1/6 | ☐ | ☐ | ☐ |
| MQTT | 1/5 | ☐ | ☐ | ☐ |
| OPC-UA | 1/3 | ☐ | ☐ | ☐ |

---

## Troubleshooting

### Alert not firing?

1. Check Wazuh loaded the rules:
   ```bash
   /var/ossec/bin/wazuh-logtest
   # Paste a JSON log line and see if it matches
   ```
2. Check your source IP isn't in the CDB allowlist:
   ```bash
   cat /var/ossec/etc/lists/authorized_modbus_masters
   ```
3. Check decoder is loaded:
   ```bash
   grep "modbus" /var/ossec/logs/ossec.log | tail -5
   ```

### OpenPLC not responding?

```bash
# Inside OpenPLC VM
sudo systemctl status openplc  # or check with ps aux | grep openplc
sudo ./start_openplc.sh
```

---

*OT Sentinel — Lab Testing Guide v1.0*
