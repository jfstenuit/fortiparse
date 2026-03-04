SECTION = "2_policies"
TITLE = "Unjustified NAT configuration"


def _has_nat(policy_data):
    """Check if a policy has NAT enabled."""
    # FortiGate NAT can be indicated by various fields
    srcnat = policy_data.get("srcnat")
    dstnat = policy_data.get("dstnat")
    nat = policy_data.get("nat")
    nat_outgoing = policy_data.get("nat-outgoing")
    nat_incoming = policy_data.get("nat-inbound")
    ippool = policy_data.get("ippool")
    poolname = policy_data.get("poolname")

    # Check if any NAT is enabled/configured
    has_nat = False
    if srcnat or dstnat or nat:
        has_nat = True
    if nat_outgoing or nat_incoming:
        has_nat = True
    if ippool or poolname:
        has_nat = True

    return has_nat


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


def _has_documentation(policy_data):
    """Check if policy has a comment or description."""
    comment = policy_data.get("comment", "")
    comments = policy_data.get("comments", "")
    description = policy_data.get("description", "")

    return bool(comment or comments or description)


def run(vdom):
    """Detect policies with NAT configured but lacking proper justification.

    NAT rules should include clear documentation explaining why NAT is needed
    for that traffic. Rules with NAT but no comment, or NAT on overly permissive
    rules, suggest misconfiguration or incomplete setup that should be reviewed.
    """
    findings = []

    policies = vdom.get("firewall", {}).get("policy", []) or []

    unjustified_nat = []

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            if not _has_nat(policy_data):
                continue

            policy_name = policy_data.get("name", f"Policy {policy_id}")
            issues = []

            # Check for missing documentation
            if not _has_documentation(policy_data):
                issues.append("no documentation")

            # Check for NAT on overly permissive rules
            if _is_permissive_rule(policy_data):
                issues.append("permissive rule (any→any + all services)")

            # Check for both srcnat and dstnat together (unusual)
            srcnat = policy_data.get("srcnat")
            dstnat = policy_data.get("dstnat")
            if srcnat and dstnat:
                issues.append("both srcnat and dstnat configured")

            if issues:
                unjustified_nat.append((policy_id, policy_name, issues))

    if not unjustified_nat:
        return []

    findings.append(
        (
            "### Unjustified NAT configuration detected\n\n"
            "Policies with NAT enabled should include clear documentation explaining "
            "the business justification. NAT rules without comments, or NAT on overly "
            "permissive rules, should be reviewed for correctness and proper configuration.\n"
        )
    )

    for policy_id, policy_name, issues in unjustified_nat:
        issue_str = "; ".join(issues)
        findings.append(f"* Policy **{policy_id}** ({policy_name}): {issue_str}")

    findings.append("")
    return findings
