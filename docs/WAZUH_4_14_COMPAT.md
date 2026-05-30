# Wazuh 4.14+ Rule Compatibility Guide

> **If you deploy OT Sentinel rules and Wazuh won't start or rules don't fire, this guide fixes it.**
>
> Verified against: Wazuh v4.14.5 (upgraded from v4.8.2)
> Tested: All 8 Modbus rules + 1 per DNP3/IEC104/MQTT/OPC-UA via `wazuh-logtest`

---

## Quick Fix — Deploy the Correct Rules

OT Sentinel v1.0+ includes Wazuh 4.14-compatible rules in the repo. If you cloned before the fix:

```bash
cd ot-sentinel && git pull
sudo cp rules/wazuh/*/*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

If you're running Wazuh **4.8 or older**, the original rule format works. Only 4.9+ need these changes.

---

## Symptom → Fix Map

| Symptom | Error Message | Fix |
|---------|--------------|-----|
| Wazuh won't start | `Invalid decoder type 'json'` | Upgrade to Wazuh 4.9+, or remove decoders with `<type>json</type>` |
| Wazuh won't start | `'group' is not a valid element` | Rules are double-wrapped. Delete and redeploy fresh from repo |
| Wazuh won't start | `Invalid root element "rule"` | Rules must be wrapped in `<group name="...">` — run `git pull` |
| Wazuh won't start | `Field 'protocol' is static` | `<protocol>` is a reserved Wazuh 4.14 tag. Remove `<field name="protocol">` from rules |
| Wazuh won't start | `Syntax error on tag 'function_code'` | Add `type="pcre2"` to all `<field>` elements with regex |
| Wazuh won't start | `Invalid option 'frequency'` | `<frequency>` must be an attribute on `<rule>`, not a child element |
| Rules match wrong rule ID | Alert shows tracker ID instead of expected | Trackers need `noalert="1"` — run `git pull` |
| No alerts at all | Logs show no matching rules | CDB lists not registered in `ossec.conf` |

---

## Complete Checklist

### 1. Rule File Format (v4.9+)

Every `.xml` rule file must start with `<group name="...">` and end with `</group>`.

```xml
<!-- ✅ CORRECT (v4.9+) -->
<group name="ot-sentinel,modbus,">
  <rule id="200001" level="12">
    <decoded_as>json</decoded_as>
    <field name="function_code" type="pcre2">^(5|15)$</field>
    ...
  </rule>
</group>

<!-- ❌ WRONG (v4.8 only) -->
<rule id="200001" level="12">
  ...
</rule>
```

### 2. Field Types (v4.9+)

All `<field>` elements using regex must specify `type="pcre2"`:

```xml
<!-- ✅ CORRECT -->
<field name="function_code" type="pcre2">^(5|15)$</field>

<!-- ❌ WRONG (works in v4.8, fails in v4.14) -->
<field name="function_code">^(5|15)$</field>
```

### 3. Reserved Field Names (v4.14+)

Wazuh has built-in tags that conflict with decoded field names:

| Reserved Word | Use Instead | Example |
|--------------|-------------|---------|
| `protocol` | Route logs by log source instead | `<localfile>` configuration handles protocol routing |

**Do NOT use `<field name="protocol">` in rules.** These are removed from OT Sentinel v1.0+ rules.

### 4. Frequency Rules (v4.9+)

The `<frequency>` tag is now an **attribute** on `<rule>`, not a child element:

```xml
<!-- ✅ CORRECT (v4.9+) -->
<rule id="200006" level="6" frequency="50" timeframe="300" ignore="5">
  <if_matched_sid>200005</if_matched_sid>
  <same_srcip />
  ...
</rule>

<!-- ❌ WRONG (v4.8 only) -->
<rule id="200006" level="6">
  <if_matched_sid>200005</if_matched_sid>
  <frequency count="50" timeframe="300">5</frequency>
  <same_source_ip />
  ...
</rule>
```

### 5. Deprecated Tags (v4.9+)

| Old (v4.8) | New (v4.9+) |
|-----------|-------------|
| `<same_source_ip />` | `<same_srcip />` |
| `<not_same_source_ip />` | `<different_srcip />` |

### 6. Tracker Rules (v4.14+)

Level 0 "tracker" rules (used for frequency counting) need `noalert="1"`:

```xml
<!-- ✅ CORRECT — silently counts, doesn't block specific rules -->
<rule id="200007" level="0" noalert="1">
  <decoded_as>json</decoded_as>
  <field name="event_type" type="pcre2">^request$</field>
  <description>Tracker: any request</description>
</rule>

<!-- ❌ WRONG — consumes the event, specific rules never fire -->
<rule id="200007" level="0">
  <decoded_as>json</decoded_as>
  <field name="event_type" type="pcre2">^request$</field>
  <description>Tracker: any request</description>
</rule>
```

### 7. CDB Lists Must Be Registered

In `/var/ossec/etc/ossec.conf`, inside `<ruleset>`:

```xml
<list>etc/lists/authorized_modbus_masters</list>
<list>etc/lists/known_modbus_masters</list>
<list>etc/lists/known_dnp3_outstations</list>
<list>etc/lists/authorized_dnp3_masters</list>
<list>etc/lists/authorized_iec104_clients</list>
<list>etc/lists/known_iec104_ioas</list>
<list>etc/lists/authorized_opcua_clients</list>
<list>etc/lists/known_mqtt_clients</list>
```

---

## Testing Rules

Use `wazuh-logtest` to test individual rules without restarting Wazuh:

```bash
# Test a specific rule
echo '{"protocol":"modbus","source_ip":"192.168.56.1","function_code":5,"event_type":"request"}' \
  | sudo /var/ossec/bin/wazuh-logtest

# Check for errors after deploying rules
sudo tail -20 /var/ossec/logs/ossec.log | grep -E "ERROR|CRITICAL"
```

### Expected Output

A successful test shows:
```
**Phase 3: Completed filtering (rules).
	id: '200001'
	level: '12'
	description: 'OT Sentinel: Unauthorized Modbus coil write from 192.168.56.1'
```

If you see `id: '200007'` (a tracker) instead, the tracker needs `noalert="1"`.

---

## Verified Test Results (Wazuh 4.14.5)

### Modbus — All 8 Rules

| Rule ID | Attack Pattern | Test Input | Result |
|---------|---------------|-----------|--------|
| 200001 | Unauthorized Coil Write | FC05, request | ✅ |
| 200002 | Unauthorized Register Write | FC06, request | ✅ |
| 200003 | Rogue Master | FC01, request | ✅ |
| 200004 | Illegal Function Code | FC72, request | ✅ |
| 200005 | Mass Read Tracker | FC03, request | 🟡 Silent tracker |
| 200006 | Mass Read Alert | 50+ FC03 in 5min | 🟡 Freq trigger |
| 200007 | Rapid Poll Tracker | FC08, request | 🟡 Silent tracker |
| 200008 | Rapid Poll Alert | 200+ requests in 5min | 🟡 Freq trigger |
| 200009 | Exception Tracker | FC131, response | 🟡 Silent tracker |
| 200010 | Exception Flood Alert | 30+ exceptions in 5min | 🟡 Freq trigger |
| 200011 | Non-Standard Port | Port 1502 | ✅ |

### DNP3 / IEC 104 / MQTT / OPC-UA — 1 Rule Each

| Rule ID | Protocol | Test Input | Result |
|---------|----------|-----------|--------|
| 200012 | DNP3 | FC130, response, unknown outstation | ✅ |
| 200022 | IEC 104 | STARTDT_act from unknown IP | ✅ |
| 200030 | MQTT | CONNECT, no credentials | ✅ |
| 200039 | OPC-UA | Write, unauthorized IP | ✅ |

---

## Still Not Working?

1. Check Wazuh loaded the rules: `sudo grep -r "200001" /var/ossec/logs/ossec.log`
2. Check decoders are loaded: `ls /var/ossec/etc/decoders/`
3. Check CDB lists are in place: `ls /var/ossec/etc/lists/`
4. Verify your log source is sending JSON: `cat /var/ossec/logs/modbus/modbus_tap.log | head -1 | python3 -m json.tool`
5. Open an issue on GitHub with your Wazuh version and error log

---

*OT Sentinel v1.0 — Wazuh Compatibility Guide*
