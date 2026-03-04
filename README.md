# Fortiparse

A comprehensive, modular audit tool for Fortigate firewall configurations that detects common anti-patterns, misconfigurations, and operational inconsistencies. The tool produces detailed, actionable audit reports in Markdown format.

## Project Scope

Fortiparse analyzes Fortigate firewall configuration backups to identify:
- **Object-level issues:** Duplicate objects, naming inconsistencies, unused objects, overly broad definitions
- **Policy anti-patterns:** Overly permissive rules, redundant/duplicate rules, disabled rules, misconfigurations
- **Configuration risks:** Missing documentation, weak configurations, suboptimal deployments

The tool produces human-readable Markdown reports that enable security and operations teams to improve firewall posture and simplify configuration management.

## Architecture

The project follows a three-stage pipeline:

### 1. Configuration Parsing (`forti_yaml_parser.py`)
Ingests Fortigate configuration backups in pseudo-YAML format and transforms them into structured JSON. This stage normalizes the configuration format for downstream analysis.

**Input:** Fortigate `.yaml` configuration backup file (pseudo-YAML format)  
**Output:** Structured JSON representation of the configuration

### 2. Audit Engine (`audit_runner.py`)
Dynamically loads and executes audit rules against the parsed configuration. Rules are organized into logical sections, findings are aggregated, and formatted output is produced.

**Input:** JSON configuration from the parser  
**Output:** Markdown report with findings organized by section

### 3. Report Generation
Section aggregators render findings into human-readable Markdown reports with context and recommendations. The output can be further transformed using tools like [Pandoc](https://pandoc.org/) for alternative formats (PDF, HTML, DOCX).

## Implemented Audit Rules

### Section 1 – Objects (10 rules)
- ✅ Detect duplicate IP addresses
- ✅ Detect duplicate ranges
- ✅ Detect duplicate FQDN
- ✅ Detect naming inconsistency (underscore, dash, camelCase, snake_case, etc.)
- ✅ Detect host /32 explosion (excessive individual host objects)
- ✅ Detect tiny ranges (ranges with < 5 IPs)
- ✅ Detect broad services (ALL, ALL_TCP, ALL_UDP)
- ✅ Detect custom services with random/non-standard ports
- ✅ Detect oversized groups mixing unrelated members
- ✅ Detect unused objects (not referenced in any policy)

### Section 2 – Policies (5 rules implemented, 1 remaining)
- ✅ Detect allow-any rules (any→any + all services)
- ✅ Detect redundant / duplicate rules (identical source/destination/service)
- ✅ Detect "copy-of" rules (temporary test rules left behind)
- ✅ Detect disabled rules (rules that clutter the config)
- ✅ Detect unjustified NAT (NAT without documentation)
- ⏳ Detect ippool misuse (planned)

### Sections 3-6 (Planned)
- Section 3 – UTM (SSL inspection, exemptions, DLP, IPS, antivirus)
- Section 4 – VPNs (weak crypto, DH parameters, PFS, keylife)
- Section 5 – Interfaces / Management (exposed management, weak certs)
- Section 6 – Dashboards (redundant widgets)

## Quick Start

### Prerequisites
- Python 3.7+
- Fortigate configuration backup file in YAML format

### Usage

```bash
# Step 1: Parse Fortigate configuration to JSON
python forti_yaml_parser.py -o json input_config.yaml > config.json

# Step 2: Run audit on a specific VDOM
python audit_runner.py --config config.json --vdom CORP-FW --output report.md

# Step 3: View the report
cat report.md

# Step 4 (Optional): Convert to other formats using Pandoc
pandoc report.md -o report.pdf
pandoc report.md -o report.html
pandoc report.md -o report.docx
```

## Development

### Creating a New Audit Rule

See [RULES_DEVELOPMENT.md](RULES_DEVELOPMENT.md) for comprehensive guidelines. Quick example:

```python
# rules/rule_my_check.py
SECTION = "2_policies"

def run(vdom):
    """Detect [specific issue]."""
    findings = []
    policies = vdom.get("firewall", {}).get("policy", [])
    
    for entry in policies:
        if isinstance(entry, dict):
            for policy_id, policy_data in entry.items():
                if isinstance(policy_data, dict) and some_condition(policy_data):
                    findings.append(...)
    
    if not findings:
        return []
    
    findings.insert(0, "### Finding Category\n\nExplanation.\n")
    return findings
```

### Contributing

1. Create a new rule following the pattern in `RULES_DEVELOPMENT.md`
2. Test with synthetic data before integration
3. Ensure section aggregator exists (e.g., `section_2_policies.py`)
4. Run full audit to verify findings appear correctly:
   ```bash
   python audit_runner.py --config config.json --vdom CORP-FW --output test_report.md
   ```
5. Commit rule and update TODO.md

## File Structure

```
fortiparse/
├── README.md                          # This file
├── RULES_DEVELOPMENT.md               # Guidelines for creating audit rules
├── TODO.md                            # Roadmap and implementation status
├── audit_runner.py                    # Main audit orchestrator
├── forti_yaml_parser.py               # Configuration parser
├── rules/
│   ├── __init__.py
│   ├── rule_duplicate_ip.py           # Audit rules
│   ├── rule_duplicate_range.py
│   ├── rule_naming_inconsistency.py
│   ├── ... (more audit rules)
│   ├── section_1_objects.py           # Section formatters
│   ├── section_2_policies.py
│   └── ... (more section formatters)
├── config.json                        # Parsed configuration (generated)
└── report.md                          # Audit report output (generated)
```

## Documentation

- [RULES_DEVELOPMENT.md](RULES_DEVELOPMENT.md) - Complete guide for developing new audit rules, including architecture, data patterns, best practices, and examples
- [TODO.md](TODO.md) - Implementation roadmap and status of planned checks
