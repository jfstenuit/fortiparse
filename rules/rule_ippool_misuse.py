SECTION = "2_policies"
TITLE = "IP pool misuse in policies"


def _has_ippool(policy_data):
    """Check if a policy references an IP pool."""
    ippool = policy_data.get("ippool")
    poolname = policy_data.get("poolname")
    return bool(ippool or poolname)


def _get_ippool_reference(policy_data):
    """Extract the IP pool reference from a policy."""
    ippool = policy_data.get("ippool")
    poolname = policy_data.get("poolname")
    return ippool or poolname


def _has_documentation(policy_data):
    """Check if policy has a comment or description."""
    comment = policy_data.get("comment", "")
    comments = policy_data.get("comments", "")
    description = policy_data.get("description", "")
    return bool(comment or comments or description)


def _is_permissive_rule(policy_data):
    """Check if rule is permissive (all addresses + all services)."""
    srcaddr = policy_data.get("srcaddr")
    dstaddr = policy_data.get("dstaddr")
    service = policy_data.get("service")

    # Check addresses
    src_is_all = False
    dst_is_all = False
    svc_is_all = False

    if isinstance(srcaddr, str):
        src_is_all = srcaddr.lower() in {"all", "any"}
    if isinstance(dstaddr, str):
        dst_is_all = dstaddr.lower() in {"all", "any"}
    if isinstance(service, str):
        svc_is_all = service.upper() in {"ALL", "ALL_TCP", "ALL_UDP"}

    return src_is_all and dst_is_all and svc_is_all


def _get_defined_ippools(vdom):
    """Extract all defined IP pool names from the firewall configuration."""
    defined_pools = set()
    
    # Check firewall.ippool objects
    ippools = vdom.get("firewall", {}).get("ippool", []) or []
    
    for entry in ippools:
        if isinstance(entry, dict):
            for pool_name in entry.keys():
                if pool_name:  # ensure non-empty name
                    defined_pools.add(pool_name.lower())
    
    return defined_pools


def run(vdom):
    """Detect policies with potentially misconfigured or suspicious IP pool usage.

    IP pools are used for NAT operations. Policies that reference IP pools without
    documentation, or reference non-existent pools, or use pools in overly
    permissive rules suggest misconfiguration or incomplete setup that should
    be reviewed.
    """
    findings = []
    
    policies = vdom.get("firewall", {}).get("policy", []) or []
    defined_pools = _get_defined_ippools(vdom)
    
    ippool_issues = []
    
    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue
            
            if not _has_ippool(policy_data):
                continue
            
            policy_name = policy_data.get("name", f"Policy {policy_id}")
            pool_ref = _get_ippool_reference(policy_data)
            issues = []
            
            # Check for missing documentation
            if not _has_documentation(policy_data):
                issues.append("no documentation")
            
            # Check if referenced pool exists (if we have defined pools)
            if defined_pools and pool_ref:
                pool_ref_lower = pool_ref.lower() if isinstance(pool_ref, str) else ""
                if pool_ref_lower and pool_ref_lower not in defined_pools:
                    issues.append(f"references undefined pool '{pool_ref}'")
            
            # Check for ippool on overly permissive rules
            if _is_permissive_rule(policy_data):
                issues.append("permissive rule (any→any + all services)")
            
            # Check for both ippool and direct NAT configuration together
            srcnat = policy_data.get("srcnat")
            dstnat = policy_data.get("dstnat")
            if (srcnat or dstnat) and pool_ref:
                issues.append("both direct NAT and ippool configured")
            
            if issues:
                ippool_issues.append((policy_id, policy_name, pool_ref, issues))
    
    if not ippool_issues:
        return []
    
    findings.append(
        (
            "### IP pool misuse detected\n\n"
            "Policies that reference IP pools should include documentation explaining "
            "the business justification. Pools should exist in the configuration, and "
            "IP pool usage should not be combined with other NAT methods or used in "
            "overly permissive rules. Policies flagged here should be reviewed for "
            "correctness and proper configuration.\n"
        )
    )
    
    for policy_id, policy_name, pool_ref, issues in ippool_issues:
        issue_str = "; ".join(issues)
        findings.append(f"* Policy **{policy_id}** ({policy_name}) [pool: {pool_ref}]: {issue_str}")
    
    findings.append("")
    return findings
