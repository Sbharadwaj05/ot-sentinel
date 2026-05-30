# OT Sentinel — Test Suite

> Automated and manual test scripts for validating OT Sentinel detection rules against real and simulated OT protocol traffic.

---

## Prerequisites

```bash
pip install pymodbus paho-mqtt pyyaml
```

Optional (for IEC 104 testing):
```bash
pip install lib60870
```

---

## Running Tests

### Individual Test

```bash
cd tests/modbus/
python test_unauthorized_write.py --target 192.168.1.100 --port 502
```

### Full Test Suite (via Test Runner)

```bash
cd tests/framework/
python test_runner.py --protocol modbus --target 192.168.1.100
```

---

## Test Structure

```
tests/
├── README.md                  # This file
├── framework/
│   ├── test_runner.py         # Automated test harness
│   └── validator.py           # Rule validation utility
├── modbus/
│   ├── test_unauthorized_write.py         # MOD-001 — unauthorized coil write
│   ├── test_unauthorized_register_write.py # MOD-002 — unauthorized register write
│   ├── test_rogue_master.py               # MOD-003 — rogue master detection
│   ├── test_illegal_function.py           # MOD-004 — illegal function code
│   ├── test_mass_read.py                  # MOD-005 — mass register read
│   ├── test_rapid_polling.py              # MOD-006 — rapid polling DoS
│   ├── test_exception_flood.py            # MOD-007 — exception flood
│   ├── test_nonstandard_port.py           # MOD-008 — non-standard port
│   └── expected_alerts.json               # Expected alert definitions
├── dnp3/
│   └── README.md              # Stub — test scripts planned for v1.1
├── iec104/
│   └── README.md              # Stub — test scripts planned for v1.1
└── mqtt/
    └── README.md              # Stub — test scripts planned for v1.1
```

---

## Expected Alert Format

Each protocol directory contains `expected_alerts.json` defining the expected
Wazuh alert for each test case. The test runner validates that actual alerts
match expected fields.

---

## Writing New Tests

1. Create `tests/<protocol>/test_<rule_name>.py`
2. Follow the template in existing test scripts
3. Add expected alert to `tests/<protocol>/expected_alerts.json`
4. Run: `python test_<rule_name>.py --target <TARGET_IP>`

Every test script must:
- Accept `--target` and `--port` arguments
- Include a `cleanup()` function
- Print the expected Wazuh alert at the end
- Be self-contained with no hidden dependencies

---

*OT Sentinel — Phase 0: Test Framework*
