SECTION = "2_policies"
TITLE = "Disabled firewall rules"


def run(vdom):
    """Detect disabled firewall policies in the configuration.

    Disabled rules clutter the ruleset and make it harder to maintain.
    Rules that are no longer needed should be removed rather than disabled.
    If a rule is temporarily disabled for testing, it should be re-enabled
    or removed as soon as testing completes.
    """
    findings = []

    policies = vdom.get("firewall", {}).get("policy", []) or []

    disabled_rules = []

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            # Check for disabled status
            disabled = policy_data.get("disable")
            if disabled:
                # Value might be number (1) or boolean (true) or string ("yes")
                if isinstance(disabled, (bool, int)):
                    is_disabled = bool(disabled)
                elif isinstance(disabled, str):
                    is_disabled = disabled.lower() in {"yes", "true", "1", "enable"}
                else:
                    is_disabled = False

                if is_disabled:
                    policy_name = policy_data.get("name", f"Policy {policy_id}")
                    disabled_rules.append((policy_id, policy_name))

    if not disabled_rules:
        return []

    findings.append(
        (
            "### Disabled firewall rules detected\n\n"
            "Disabled policies remaining in the configuration clutter the ruleset and increase "
            "maintenance burden. Rules that are no longer needed should be deleted entirely rather "
            "than disabled. If rules are temporarily disabled for testing, they should be re-enabled "
            "or removed as soon as testing is complete.\n"
        )
    )

    for policy_id, policy_name in disabled_rules:
        findings.append(f"* Policy **{policy_id}** ({policy_name}) — disabled")

    findings.append("")
    return findings
