SECTION = "1_objects"
TITLE = "Wildcard FQDN Objects"


def run(vdom):
    """Detect wildcard FQDN objects used in firewall addresses."""
    wildcard_fqdns = []

    addrs = vdom.get("firewall", {}).get("address", [])

    for entry in addrs:
        # Each entry is a dict like {"obj_name": {obj_properties}}
        if not isinstance(entry, dict):
            continue
            
        for obj_name, obj_data in entry.items():
            # Skip if obj_data is not a dict (e.g., empty entries)
            if not isinstance(obj_data, dict):
                continue
                
            if obj_data.get("type") == "fqdn":
                fqdn = obj_data.get("fqdn", "")
                if fqdn.startswith("*."):
                    wildcard_fqdns.append((obj_name, fqdn))

    if not wildcard_fqdns:
        return []

    # Format findings as a single markdown block
    findings = [
        "### Wildcard FQDN used in objects\n\n"
        "Wildcard FQDNs in firewall address objects can create security issues by matching "
        "more domains than intended. Consider using more specific FQDNs where possible.\n"
    ]
    
    for obj_name, fqdn in wildcard_fqdns:
        findings.append(f"* **{obj_name}**: {fqdn}")

    findings.append("")  # final newline

    return findings