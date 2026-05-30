# Security Policy

## Reporting a Vulnerability

OT Sentinel is a detection rule library. A vulnerability in a detection rule
could mean false negatives — real attacks going undetected. We take this
seriously.

### Private Reporting

**Do NOT open a public issue** for security-sensitive bugs. Instead, email:

```
subhash [at] protonmail [dot] com
```

PGP key available on request.

### What to Include

- Which rule file(s) are affected (e.g., `rules/wazuh/modbus/modbus_unauthorized_write.xml`)
- The specific detection gap (what attack pattern is missed)
- A sample log line or traffic description that should trigger but doesn't
- Your Wazuh version

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledge receipt | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix published | Within 30 days (critical), 60 days (non-critical) |

### Scope

This policy covers detection rule logic errors, missing attack patterns,
and deployment issues that could cause false negatives. It does NOT cover:

- General Wazuh bugs (report to Wazuh directly)
- Feature requests (open a regular GitHub issue)
- Documentation typos (open a PR)

---

## Supported Versions

| Version | Wazuh Compatibility | Status |
|---------|-------------------|--------|
| v1.0.0 | 4.9 - 4.14+ | ✅ Supported |
| < v1.0.0 | — | ❌ Pre-release only |

---

*OT Sentinel — Security Policy*
