SECTION = "2_policies"
TITLE = "Copy-of rules detected"


def run(vdom):
    """Detect firewall policies with 'copy-of' naming pattern.

    Rules with names like "copy-of-Rule_123" or similar indicate temporary
    test/development rules that were likely copied for testing and left behind.
    These rules should be reviewed and removed if no longer needed. They often
    represent transient configuration changes that should not be in production.
    """
    findings = []

    policies = vdom.get("firewall", {}).get("policy", []) or []

    copyof_rules = []

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            policy_name = policy_data.get("name", "")
            if not policy_name:
                continue

            # Check for "copy-of" pattern in name (case-insensitive)
            if "copy-of" in policy_name.lower():
                copyof_rules.append((policy_id, policy_name))

    if not copyof_rules:
        return []

    findings.append(
        (
            "### Copy-of rules detected\n\n"
            "Policies with 'copy-of' in their name typically indicate temporary test rules "
            "that were created by copying existing rules during development and left behind. "
            "These rules should be reviewed, properly renamed or consolidated, and removed "
            "if they are no longer needed. Leaving test rules in production increases clutter "
            "and maintenance burden.\n"
        )
    )

    for policy_id, policy_name in copyof_rules:
        findings.append(f"* Policy **{policy_id}**: {policy_name}")

    findings.append("")
    return findings
