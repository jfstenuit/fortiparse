SECTION = "3_utm"
TITLE = "Excessive SSL/TLS exemptions"

# Threshold for flagging excessive exemptions
EXCESSIVE_EXEMPTION_THRESHOLD = 20


def _count_ssl_exemptions(profile_data):
    """Count the number of SSL exemption rules in a profile."""
    ssl_exempt = profile_data.get("ssl-exempt", [])
    if isinstance(ssl_exempt, list):
        return len(ssl_exempt)
    return 0


def _get_exemption_details(profile_data):
    """Extract details about exemption rules."""
    ssl_exempt = profile_data.get("ssl-exempt", [])
    if not isinstance(ssl_exempt, list):
        return []
    
    details = []
    for entry in ssl_exempt:
        if isinstance(entry, dict):
            for exemption_id, exemption_data in entry.items():
                if isinstance(exemption_data, dict):
                    # Extract the exemption type/target
                    if "fortiguard-category" in exemption_data:
                        cat = exemption_data.get("fortiguard-category")
                        details.append(f"category {cat}")
                    elif "wildcard-fqdn" in exemption_data:
                        fqdn = exemption_data.get("wildcard-fqdn")
                        details.append(f"FQDN: {fqdn}")
                    elif "type" in exemption_data:
                        ex_type = exemption_data.get("type")
                        details.append(f"type: {ex_type}")
    
    return details


def run(vdom):
    """Detect SSL/TLS inspection profiles with excessive exemptions.

    SSL exemptions bypass inspection for specified sites/categories. While some
    exemptions are necessary (e.g., incompatible sites, internal resources),
    excessive exemptions significantly reduce threat coverage and should be
    reviewed to ensure they are justified and necessary.
    """
    findings = []
    
    ssl_ssh_profiles = vdom.get("firewall", {}).get("ssl-ssh-profile", []) or []
    
    excessive_exemption_profiles = []
    
    for profile_entry in ssl_ssh_profiles:
        if not isinstance(profile_entry, dict):
            continue
        
        for profile_name, profile_data in profile_entry.items():
            if not isinstance(profile_data, dict):
                continue
            
            exempt_count = _count_ssl_exemptions(profile_data)
            
            if exempt_count > EXCESSIVE_EXEMPTION_THRESHOLD:
                details = _get_exemption_details(profile_data)
                excessive_exemption_profiles.append((profile_name, exempt_count, details))
    
    if not excessive_exemption_profiles:
        return []
    
    findings.append(
        (
            "### Excessive SSL/TLS exemptions detected\n\n"
            "SSL inspection exemptions bypass threat inspection for specified sites and "
            "categories. While some exemptions are necessary for compatibility or internal "
            "resources, excessive exemptions create blind spots in threat detection. Profiles "
            "with more than {threshold} exemptions should be reviewed to ensure each exemption "
            "is documented and justified.\n".format(threshold=EXCESSIVE_EXEMPTION_THRESHOLD)
        )
    )
    
    for profile_name, exempt_count, details in excessive_exemption_profiles:
        findings.append(
            f"* **{profile_name}**: {exempt_count} exemptions (threshold: {EXCESSIVE_EXEMPTION_THRESHOLD})"
        )
        # Show a sample of exemptions (limit to 5 for brevity)
        if details:
            sample = details[:5]
            for detail in sample:
                findings.append(f"  - {detail}")
            if len(details) > 5:
                remaining = len(details) - 5
                findings.append(f"  - ... and {remaining} more exemptions")
    
    findings.append("")
    return findings
