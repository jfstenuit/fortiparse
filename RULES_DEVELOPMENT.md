# Rules Development Guide

This document explains how to develop new audit rules for the fortiparse audit engine.

## Architecture Overview

The audit system consists of three main components:

1. **audit_runner.py** - Main orchestrator that loads rules, executes them, and generates the report
2. **config.json** - Configuration input containing FortiGate VDOM data
3. **rules/** - Directory containing audit rule modules organized by section

```
audit_runner.py (loads rules, aggregates config, orchestrates execution)
        ↓
    loads rules from rules/
        ↓
    groups by SECTION key
        ↓
    executes audit_* rules → collect findings
        ↓
    passes findings to section_* aggregator
        ↓
    section_* renders markdown output
        ↓
    combines all sections into report.md
```

## Config Structure

The `config.json` contains a `vdom` array where each element is a dictionary. **The same VDOM name can appear multiple times, and all entries are merged together.**

```json
{
  "vdom": [
    { "CORP-FW": { } },
    { "CORP-FW": { "firewall_address": [...] } },
    { "CORP-FW": { "firewall_policy": [...] } },
    { "V-HUB": { ... } }
  ]
}
```

### Data Transformation Pipeline

1. **Raw config** - Contains flat keys like `firewall_address`, `firewall_policy`, `system_settings`
2. **Extract & Merge** - `audit_runner.py` finds all instances of a VDOM and merges them
3. **Aggregate** - Splits underscore-separated keys into nested dicts:
   - `firewall_address` → `firewall.address`
   - `system_settings` → `system.settings`
   - `user_group` → `user.group`

4. **Pass to Rules** - Rules receive a **single aggregated dict** like:
```python
{
  "firewall": {
    "address": [...],
    "policy": [...],
    ...
  },
  "system": {
    "settings": {...},
    ...
  },
  "user": {
    "group": [...],
    ...
  }
}
```

## Data Format: Address Objects Example

To understand the structure rules work with, here's how firewall addresses are organized:

```python
addrs = vdom.get("firewall", {}).get("address", [])
# Result is a list of dicts, each dict has one entry:
# [
#   {"object_name": {object_properties}},
#   {"another_object": {object_properties}},
#   ...
# ]
```

Each entry is a single-key dict:
```python
{
  "FQDN_*.mail.ru": {
    "uuid": "fa7caea0-033f-51f0-8892-acbf548afe0d",
    "type": "fqdn",
    "fqdn": "*.mail.ru"
  }
}
```

To iterate:
```python
for entry in addrs:
    if isinstance(entry, dict):
        for obj_name, obj_data in entry.items():
            if isinstance(obj_data, dict):
                # access obj_name and obj_data properties
```

## Rule Types

There are two types of rule modules:

### 1. Audit Rules (rule_*.py)

These are the actual checks that detect issues.

**Template:**
```python
SECTION = "1_objects"  # Section name for grouping

def run(vdom):
    """Audit the VDOM and return a list of findings.
    
    Args:
        vdom: Aggregated VDOM dict with nested structure
    
    Returns:
        List of markdown-formatted finding strings, or empty list if no findings
    """
    findings = []
    
    # Access config data through nested structure
    # data = vdom.get("section", {}).get("subsection", [])
    
    # Perform checks
    # if condition_met:
    #     findings.append("markdown formatted finding")
    
    return findings
```

**Finding Format:**

Amways return a markdown block with an introduction to the findings :
```python
findings = [
    "### Finding Title\n\n"
    "Explanation of why this matters.\n"
]

for item in problematic_items:
    findings.append(f"* **{item['name']}**: Details")

return findings
```

### 2. Section Aggregators (section_*.py)

These render the final markdown output for a section. They receive all findings from audit rules in that section and format them nicely.

**Template with Context Introduction (Recommended):**
```python
SECTION = "1_objects"
TITLE = "Issues with objects (addresses, services, groups)"

def render(findings):
    """Render markdown for this section."""
    if not findings:
        return ""
    
    intro = (
        "Firewall objects form the building blocks of security policies. Poor object "
        "management leads to configuration confusion and maintenance overhead. This section "
        "audits objects for redundancy, naming inconsistency, and unused entries."
    )
    
    md = [
        f"## **{TITLE}**\n",
        f"{intro}\n",
        "Below are all findings detected in this section:\n",
    ]
    
    for finding in findings:
        md.append(finding)
    
    md.append("")  # final newline
    return "\n".join(md)
```

**Best Practice:** Each section aggregator should include a 2-3 sentence introduction explaining:
- Why this category of checks matters for security/operations
- What types of issues this section covers
- Benefit of addressing findings in this area

## Creating a New Rule

### Step 1: Create the rule file

Create `rules/rule_<descriptive_name>.py`:

```python
SECTION = "1_objects"  # Must match an existing section_*.py

def run(vdom):
    """Check for [specific issue]."""
    findings = []
    
    # Example: Check firewall addresses
    addrs = vdom.get("firewall", {}).get("address", [])
    
    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue
            
            # Your check here
            if some_condition(obj_data):
                findings.append(f"Finding: {obj_name}")
    
    # Return markdown-formatted findings
    if not findings:
        return []
    
    result = [
        "### Finding Category\n\n"
        "Explanation of the issue.\n"
    ]
    result.extend(findings)
    return result
```

### Step 2: Ensure section aggregator exists

Verify `rules/section_<section_name>.py` exists. If not, create it:

```python
SECTION = "1_objects"
TITLE = "Objects Issues"

def render(findings):
    if not findings:
        return ""
    
    md = [f"## **{TITLE}**\n", "Below are all findings:\n"]
    md.extend(findings)
    md.append("")
    return "\n".join(md)
```

### Step 3: Test the rule

```bash
python audit_runner.py --config config.json --vdom "SAB-FW" --output test_report.md
```

Check `test_report.md` to verify your findings appear.

## Accessing Data in Rules

### Common Patterns

**Firewall Addresses:**
```python
addrs = vdom.get("firewall", {}).get("address", [])
for entry in addrs:
    if isinstance(entry, dict):
        for obj_name, obj_data in entry.items():
            fqdn = obj_data.get("fqdn", "")
```

**Firewall Policies:**
```python
policies = vdom.get("firewall", {}).get("policy", [])
for entry in policies:
    if isinstance(entry, dict):
        for policy_id, policy_data in entry.items():
            action = policy_data.get("action", "")
```

**User Groups:**
```python
groups = vdom.get("user", {}).get("group", [])
for entry in groups:
    if isinstance(entry, dict):
        for group_name, group_data in entry.items():
            members = group_data.get("member", [])
```

**System Settings:**
```python
settings = vdom.get("system", {}).get("settings", {})
timezone = settings.get("timezone", "")
```

### Available Top-Level Sections

After aggregation, the vdom dict contains these top-level keys:
- firewall
- system
- switch-controller
- vpn
- webfilter
- ips
- web-proxy
- application
- log
- icap
- user
- voip
- dnsfilter
- antivirus
- emailfilter
- waf
- casb
- authentication
- wireless-controller
- endpoint-control
- router

Each section may have multiple subsections (e.g., `firewall.address`, `firewall.policy`).

## Rule Loading and Execution

The workflow is:

1. `load_rules()` - Dynamically imports all modules with a `SECTION` attribute
2. Rules are grouped by `SECTION` value
3. Within each section:
   - `audit_*` rules (those not starting with `section_`) are executed
   - Their findings are collected
   - `section_*` rule renders the findings as markdown
4. Final markdown is written to the output file

## Best Practices

1. **Type Safety** - Always check `isinstance()` before calling dict methods:
   ```python
   if isinstance(entry, dict):
       for key, data in entry.items():
           if isinstance(data, dict):
               # safe to access data
   ```

2. **Graceful Degradation** - Use `.get()` with defaults for optional fields:
   ```python
   fqdn = obj_data.get("fqdn", "")
   uuid = obj_data.get("uuid", "unknown")
   ```

3. **Handle List/String Duality** - Many config fields can be either string or list:
   ```python
   srcaddr = policy_data.get("srcaddr")
   if isinstance(srcaddr, str):
       srcaddr = [srcaddr]
   # Now safe to iterate as list
   ```

4. **Normalize for Comparison** - When comparing values (especially for duplicates):
   - Convert to lowercase for case-insensitive matching: `val.lower()`
   - Sort lists before creating signatures: `tuple(sorted(items))`
   - Strip whitespace: `val.strip()`
   - This ensures order-independent and case-independent duplicate detection

5. **Count & Threshold Rules** - For rules that count occurrences:
   - Define a clear threshold constant: `THRESHOLD = 20`
   - Return empty if threshold not exceeded
   - Show top 10 examples + remainder count for large results

6. **Clear Finding Format** - Structure findings with consistent markdown:
   ```python
   findings = [
       "### Finding Title\n\n"
       "1-2 sentence explanation of why this matters.\n"
   ]
   for item in items:
       findings.append(f"* **{name}**: {detail}")
   findings.append("")  # trailing newline
   ```

7. **Return Early** - If no findings, return empty list immediately:
   ```python
   if not problematic_items:
       return []
   ```

8. **Comprehensive Docstrings** - Explain what the rule checks and why:
   ```python
   def run(vdom):
       """Detect wildcard FQDNs in firewall addresses.
       
       Wildcard FQDNs (*.example.com) can match unintended domains and
       represent a security risk. This rule identifies such patterns.
       """
   ```

9. **Test with Synthetic Data** - Create test cases before integration:
   ```python
   vdom = {'firewall': {'address': [
       {'obj1': {'subnet': '10.0.0.1 255.255.255.255'}},
       {'obj2': {'subnet': '10.0.0.1 255.255.255.255'}},  # duplicate
   ]}}
   res = rule_module.run(vdom)
   assert len(res) > 0, "Should detect duplicates"
   ```

10. **Pattern-Based Checks** - For naming convention issues:
    - Use case-insensitive matching: `"copy-of" in name.lower()`
    - Document the pattern and why it indicates an issue
    - Example: "copy-of" in rule name indicates temporary test rules left behind

11. **Common Data Patterns** - Know what fields to expect:
    - **Addresses:** `subnet` (IPv4), `ip6` (IPv6), `type` (fqdn/iprange/etc)
    - **Ranges:** `start-ip`/`end-ip` (IPv4), `start-ip6`/`end-ip6` (IPv6)
    - **Services:** `tcp-portrange`, `udp-portrange`, `sctp-portrange`
    - **Policies:** `srcaddr`/`dstaddr`/`service`/`action`, `disable` flag
    - **Groups:** `member` field (always a list of object names)

## Example: Complete Rule

```python
SECTION = "1_objects"

def run(vdom):
    """Detect firewall address objects without descriptions."""
    undescribed = []
    
    addrs = vdom.get("firewall", {}).get("address", [])
    
    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue
            
            # Check if description is missing or empty
            description = obj_data.get("comment", "").strip()
            if not description:
                undescribed.append(obj_name)
    
    if not undescribed:
        return []
    
    findings = [
        "### Missing Descriptions on Address Objects\n\n"
        "Address objects should have descriptions to document their purpose. "
        "This improves maintainability and security posture.\n"
    ]
    
    for obj_name in undescribed:
        findings.append(f"* {obj_name}")
    
    return findings
```

## Troubleshooting

**Rule not loading:** Ensure it has a `SECTION` attribute at module level.

**Rule not executing:** Verify the filename matches `rule_*.py` pattern and module can be imported.

**Findings not appearing:** Check that section has a corresponding `section_*.py` aggregator.

**Data access errors:** Use defensive code with `isinstance()` checks and `.get()` with defaults.

**Empty entries in config:** The config may contain `{}` entries - always check `isinstance(data, dict)` before accessing.
