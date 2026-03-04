SECTION = "3_utm"
TITLE = "SSL/TLS inspection configuration issues"



def _is_inspection_disabled(profile_data):
    """Check if SSL inspection is disabled for HTTPS."""
    https = profile_data.get("https", {})
    if isinstance(https, dict):
        status = https.get("status", "")
        return status and status.lower() == "disable"
    return False


def _allows_untrusted_certs(profile_data):
    """Check if profile allows expired or revoked certificates."""
    protocols = ["https", "ftps", "imaps", "pop3s", "smtps", "dot"]
    issues = []
    
    for protocol in protocols:
        proto_config = profile_data.get(protocol, {})
        if isinstance(proto_config, dict):
            # Check if explicitly allowing invalid certificates
            if proto_config.get("expired-server-cert") == "allow":
                issues.append(f"{protocol.upper()} allows expired certs")
            if proto_config.get("revoked-server-cert") == "allow":
                issues.append(f"{protocol.upper()} allows revoked certs")
            if proto_config.get("cert-validation-failure") == "allow":
                issues.append(f"{protocol.upper()} allows cert validation failures")
    
    return issues


def _check_blocklisted_certs(profile_data):
    """Check if blocklisted certificate blocking is disabled."""
    return profile_data.get("block-blocklisted-certificates") == "disable"


def _is_no_inspection_profile(profile_name, profile_data):
    """Check if profile is explicitly a no-inspection profile."""
    name_lower = str(profile_name).lower()
    comment = profile_data.get("comment", "").lower()
    
    # Check for obvious no-inspection profiles
    if "no-inspection" in name_lower or "disabled" in name_lower:
        return True
    if "does no inspection" in comment or "no inspection" in comment:
        return True
    
    # Check if https inspection is disabled
    return _is_inspection_disabled(profile_data)


def run(vdom):
    """Detect SSL/TLS inspection misconfigurations in firewall profiles.

    SSL/TLS inspection is critical for identifying malware and threats in
    encrypted traffic. Profiles with disabled inspection, weak certificate
    validation, or allowance of invalid certificates
    create security gaps that should be reviewed immediately.
    """
    findings = []
    
    ssl_ssh_profiles = vdom.get("firewall", {}).get("ssl-ssh-profile", []) or []
    
    issues_found = []
    
    for profile_entry in ssl_ssh_profiles:
        if not isinstance(profile_entry, dict):
            continue
        
        for profile_name, profile_data in profile_entry.items():
            if not isinstance(profile_data, dict):
                continue
            
            profile_issues = []
            
            # Check if inspection is disabled
            if _is_no_inspection_profile(profile_name, profile_data):
                profile_issues.append("SSL/TLS inspection disabled")
            
            # Check for weak certificate validation
            cert_issues = _allows_untrusted_certs(profile_data)
            profile_issues.extend(cert_issues)
            
            # Check if blocklisted certificate blocking is disabled
            if _check_blocklisted_certs(profile_data):
                profile_issues.append("blocklisted certificate blocking disabled")
            
            if profile_issues:
                issues_found.append((profile_name, profile_issues))
    
    if not issues_found:
        return []
    
    findings.append(
        (
            "### SSL/TLS inspection configuration issues detected\n\n"
            "SSL/TLS inspection protects against threats in encrypted traffic including "
            "malware, data exfiltration, and protocol-based attacks. Profiles with disabled "
            "inspection, weak certificate validation, or allowance of "
            "invalid certificates significantly weaken this protection. These profiles should "
            "be reviewed and corrected immediately.\n"
        )
    )
    
    for profile_name, profile_issues in issues_found:
        issue_str = "; ".join(profile_issues)
        findings.append(f"* **{profile_name}**: {issue_str}")
    
    findings.append("")
    return findings
