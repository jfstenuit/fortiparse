SECTION = "2_policies"
TITLE = "Allow-any firewall rules"


def _is_permissive_address(addr_val):
    """Check if an address value represents 'any' or 'all'."""
    if isinstance(addr_val, str):
        return addr_val.lower() in {"all", "any", "0.0.0.0/0", "0.0.0.0 0.0.0.0"}
    return False


def _is_permissive_service(svc_val):
    """Check if a service value represents 'all' or broad services."""
    if isinstance(svc_val, str):
        return svc_val.upper() in {"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP"}
    return False


def run(vdom):
    """Detect firewall policies with overly permissive allow rules.

    Policies that accept traffic from any source to any destination with
    any service are extremely dangerous and likely represent either
    misconfiguration or temporary rules that were left in place.
    Such rules should be reviewed and restricted to specific use cases.
    """
    findings = []

    policies = vdom.get("firewall", {}).get("policy", []) or []

    allow_any_rules = []

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            # Only flag accept rules (deny rules are less critical)
            action = policy_data.get("action", "").lower()
            if action != "accept":
                continue

            # Check source and destination
            srcaddr = policy_data.get("srcaddr")
            dstaddr = policy_data.get("dstaddr")
            service = policy_data.get("service")

            # Normalize to lists for easier checking
            if isinstance(srcaddr, str):
                srcaddr = [srcaddr]
            if isinstance(dstaddr, str):
                dstaddr = [dstaddr]
            if isinstance(service, str):
                service = [service]

            # Check if all three dimensions are permissive
            has_any_source = any(_is_permissive_address(s) for s in (srcaddr or []))
            has_any_dest = any(_is_permissive_address(d) for d in (dstaddr or []))
            has_any_service = any(_is_permissive_service(s) for s in (service or []))

            # Flag if all three are "any"
            if has_any_source and has_any_dest and has_any_service:
                rule_name = policy_data.get("name", f"Policy {policy_id}")
                allow_any_rules.append((policy_id, rule_name))

    if not allow_any_rules:
        return []

    findings.append(
        (
            "### Allow-any firewall rules detected\n\n"
            "Policies that accept traffic from **any source → any destination → any service** "
            "are dangerously permissive and likely misconfigured or temporary rules left in place. "
            "These rules should be reviewed immediately and replaced with specific, "
            "business-justified rules.\n"
        )
    )

    for policy_id, rule_name in allow_any_rules:
        findings.append(f"* Policy **{policy_id}** ({rule_name})")

    findings.append("")
    return findings
