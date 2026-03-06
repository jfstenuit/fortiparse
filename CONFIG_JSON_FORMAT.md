# Config JSON Format Reference

This document describes the exact structure of `config.json` produced by
`forti_yaml_parser.py`. It is the authoritative reference for writing audit
rules and must be consulted before implementing any new rule or data accessor.

---

## Top-level structure

```json
{
  "global": { ... },
  "vdom":   [ ... ]
}
```

| Key      | Type            | Contents |
|----------|-----------------|----------|
| `global` | flat object     | Device-wide settings (interfaces, SNMP, certs, system_global, …). **Not tied to any VDOM.** |
| `vdom`   | array of objects | Each element is `{ "<vdom-name>": { <flat-key-dict> } }`. A single physical device can produce multiple entries with the same VDOM name (one per config block in the backup); `extract_vdom()` merges them. |

---

## Key naming convention — flat underscore-joined keys

Every configuration section is stored as a **flat key** formed by joining
FortiOS path components with underscores:

```
<section>_<subsection>[_<sub-subsection>...]
```

Examples:

| FortiOS path | JSON flat key |
|---|---|
| `config firewall address` | `firewall_address` |
| `config vpn ipsec phase1-interface` | `vpn_ipsec_phase1-interface` |
| `config vpn ipsec phase2-interface` | `vpn_ipsec_phase2-interface` |
| `config vpn ssl settings` | `vpn_ssl_settings` |
| `config vpn certificate local` | `vpn_certificate_local` |
| `config vpn certificate ca` | `vpn_certificate_ca` |
| `config system global` | `system_global` |
| `config system snmp user` | `system_snmp_user` |
| `config system interface` | `system_interface` |
| `config firewall service custom` | `firewall_service_custom` |
| `config firewall policy` | `firewall_policy` |

**Critical:** hyphens in FortiOS path components are preserved as-is in the
key (e.g., `phase1-interface`, `ssl-ssh-profile`). Only the path separator
(space) becomes `_`.

---

## `aggregate_vdom()` — how flat keys become nested dicts

`audit_runner.py` calls `aggregate_vdom()` **before** passing data to rules.
It splits each flat key on the **first underscore only**:

```python
parts = key.split("_", 1)   # split on FIRST underscore only
section, subsection = parts
aggregated[section][subsection] = value
```

Result for the examples above:

| Flat key | Aggregated path in rule |
|---|---|
| `firewall_address` | `vdom["firewall"]["address"]` |
| `vpn_ipsec_phase1-interface` | `vdom["vpn"]["ipsec_phase1-interface"]` |
| `vpn_ipsec_phase2-interface` | `vdom["vpn"]["ipsec_phase2-interface"]` |
| `vpn_ssl_settings` | `vdom["vpn"]["ssl_settings"]` |
| `vpn_certificate_local` | `vdom["vpn"]["certificate_local"]` |
| `vpn_certificate_ca` | `vdom["vpn"]["certificate_ca"]` |
| `system_global` | `vdom["system"]["global"]` |
| `system_snmp_user` | `vdom["system"]["snmp_user"]` |
| `firewall_service_custom` | `vdom["firewall"]["service_custom"]` |
| `firewall_ssl-ssh-profile` | `vdom["firewall"]["ssl-ssh-profile"]` |

**The subsection key is never split further.** Do not use three-level
`.get("vpn", {}).get("ipsec", {}).get("phase1-interface", [])` — that will
always return `{}`.

### Correct accessor pattern

```python
# CORRECT
phase1 = vdom.get("vpn", {}).get("ipsec_phase1-interface", [])
ssl_settings = vdom.get("vpn", {}).get("ssl_settings", {})
snmp_users = vdom.get("system", {}).get("snmp_user", [])
admin_cert = vdom.get("system", {}).get("global", {}).get("admin-server-cert")

# WRONG — three-level nesting does not exist after aggregation
phase1 = vdom.get("vpn", {}).get("ipsec", {}).get("phase1-interface", [])  # always []
ssl    = vdom.get("vpn", {}).get("ssl", {}).get("settings", {})             # always {}

# WRONG — flat key no longer exists after aggregation
users = vdom.get("system_snmp_user", [])    # always []
```

---

## Global data availability in rules

`audit_runner.py` merges aggregated global data into the vdom dict before
running rules. After the merge, rules can transparently access:

```python
vdom.get("system", {}).get("snmp_user", [])      # from global
vdom.get("system", {}).get("global", {})          # from global
vdom.get("certificate", {})                       # from global (if present)
```

Vdom-specific values always override global defaults when the same section
exists in both.

---

## Value shapes: two distinct patterns

### Pattern A — array of named-entry dicts

Used for all tables (address objects, policies, tunnels, certificates, …).
Each element of the array is a **single-key dict** whose key is the object's
name and whose value is the object's fields:

```json
[
  { "sap4hana": { "interface": "port3", "proposal": "aes128-sha256 ...", "dhgrp": 5 } },
  { "vpn-branch1": { "interface": "port1", "proposal": "aes256-sha256", "dhgrp": 21 } }
]
```

**Canonical iteration pattern** (same for addresses, policies, tunnels, certs,
services, …):

```python
entries = vdom.get("vpn", {}).get("ipsec_phase1-interface", [])
for entry in entries:
    if not isinstance(entry, dict):
        continue
    for name, obj in entry.items():
        if not isinstance(obj, dict):
            continue
        # use name (str) and obj (dict of fields)
```

Never do `for name, obj in entries` — a dict with one key cannot be unpacked
into two variables and will raise `ValueError`.

### Pattern B — flat settings dict

Used for singleton config blocks (`system_global`, `vpn_ssl_settings`,
`system_npu`, …). The value is a plain dict of field → value pairs:

```json
{
  "admin-port": 180,
  "hostname": "BXL-FW",
  "timezone": "Europe/Brussels"
}
```

```python
settings = vdom.get("system", {}).get("global", {})
hostname = settings.get("hostname")
```

No iteration needed; access fields directly.

---

## Field value types

Field values preserve their original types from the FortiOS configuration.
Common types encountered:

| Type | Example fields | Notes |
|------|---------------|-------|
| `int` | `dhgrp`, `keylife`, `keylifeseconds`, `port`, `admintimeout` | Numeric fields are always integers, never strings |
| `str` | `proposal`, `pfs`, `priv-proto`, `auth-proto`, `action`, `status` | Most flag fields are strings (`"enable"`, `"disable"`, `"des"`, `"md5"`) |
| `str` (space-separated) | `proposal`, `srcaddr` (sometimes) | Multi-value string fields use space as separator; split with `.split()` |
| `list` | `srcaddr`, `dstaddr`, `dstintf` when multiple values | Some multi-value fields are stored as JSON arrays |
| `null` | `keylife` when not set | Always guard with `if value is not None` or `== specific_value` |
| `str` (PEM block) | `certificate`, `private-key` | Raw PEM text; no pre-parsed crypto metadata is present |

---

## SNMP-specific notes

SNMP configuration lives **exclusively in `global`**, never in per-vdom data.
After the global merge in `audit_runner.py`, it is accessible as:

```python
snmp_users       = vdom.get("system", {}).get("snmp_user", [])       # Pattern A
snmp_communities = vdom.get("system", {}).get("snmp_community", [])  # Pattern A (may be absent)
```

Each SNMP user entry follows Pattern A:
```json
[{ "Sabcadmin": { "security-level": "auth-priv", "priv-proto": "des", "auth-pwd": "..." } }]
```

---

## Certificate-specific notes

### In vdoms
Local and CA certificates attached to VPN profiles are stored under the `vpn`
section:

```python
local_certs = vdom.get("vpn", {}).get("certificate_local", [])  # Pattern A
ca_certs    = vdom.get("vpn", {}).get("certificate_ca", [])     # Pattern A
```

### In global
Device-wide certificates (used for admin GUI, SSL inspection CA) live in
`global` and are accessible after the merge:

```python
global_local = vdom.get("certificate", {}).get("local", [])  # Pattern A, if present
```

### Certificate entry structure
Each cert entry is a named dict (Pattern A). The JSON does **not** contain
pre-parsed crypto fields (`subject`, `issuer`, `key-type`, `key-size`,
`signature-algorithm`, `valid-to`). Only the raw PEM blob and metadata added
by the parser are present:

```json
{ "Fortinet_CA_SSL": { "certificate": "-----BEGIN CERTIFICATE-----\n...", "source": "factory", "last-updated": 1738148251 } }
```

Helpers checking `subject`, `issuer`, or `key-size` will always return `False`
on this config because those fields are absent. Only `name`-based and
`source`-based heuristics (e.g., factory cert detection) are reliable.

### SSL-VPN cert reference field
The field holding the SSL-VPN server certificate name is `servercert` (no
hyphen), not `server-cert`:

```python
sslvpn = vdom.get("vpn", {}).get("ssl_settings", {})
cert_name = sslvpn.get("servercert")   # CORRECT
cert_name = sslvpn.get("server-cert")  # WRONG — always None
```

---

## VPN-specific notes

### IPsec Phase1 (Pattern A)
```python
phase1 = vdom.get("vpn", {}).get("ipsec_phase1-interface", [])
# fields per tunnel: proposal (str, space-sep), dhgrp (int), keylife (int|null),
#                    psksecret (masked str), interface (str), remote-gw (str)
```

### IPsec Phase2 (Pattern A)
```python
phase2 = vdom.get("vpn", {}).get("ipsec_phase2-interface", [])
# fields per selector: pfs ("enable"|"disable"), keylifeseconds (int|null),
#                      src-subnet (str), dst-subnet (str), phase1name (str)
```

### SSL-VPN settings (Pattern B)
```python
sslvpn = vdom.get("vpn", {}).get("ssl_settings", {})
# fields: port (int), servercert (str), banned-cipher (str, space-sep),
#         algorithm (str, if set)
```

---

## Policy-specific notes

Policies follow Pattern A but use the numeric policy ID as the name key:

```json
[{ "198": { "name": "LAN to Internet Block MAC", "srcintf": "x2", "action": "accept", ... } }]
```

Fields like `srcaddr`, `dstaddr`, `service` may be a single string **or** a
JSON array depending on whether multiple values are configured:

```python
srcaddr = policy.get("srcaddr", [])
if isinstance(srcaddr, str):
    srcaddr = [srcaddr]
```

---

## Minimal rule template

```python
SECTION = "4_vpns"   # must match an existing section_N_*.py aggregator
TITLE   = "Short human-readable title"

def run(vdom):
    findings = []

    # Pattern A — named-entry table
    entries = vdom.get("<section>", {}).get("<subsection_key>", [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name, obj in entry.items():
            if not isinstance(obj, dict):
                continue
            if some_condition(obj):
                findings.append(f"* **{name}**: description")

    # Pattern B — singleton settings dict
    settings = vdom.get("<section>", {}).get("<settings_key>", {})
    if settings.get("some-field") == "bad-value":
        findings.append("* **ComponentName**: description")

    if not findings:
        return []

    findings.insert(0, "### Finding Title\n\nExplanation.\n")
    findings.append("")  # trailing newline
    return findings
```
