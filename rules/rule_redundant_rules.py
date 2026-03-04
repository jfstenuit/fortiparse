SECTION = "2_policies"
TITLE = "Redundant / duplicate firewall rules"


def _normalize_field(val):
    """Convert address/service field to a hashable signature for comparison."""
    if val is None:
        return None
    if isinstance(val, list):
        return tuple(sorted(str(v).lower() for v in val if v))
    return (str(val).lower(),)


def run(vdom):
    """Detect firewall policies with identical rule conditions.

    Rules with the same source address(es), destination address(es), service(s),
    and action are redundant. The first matching rule will be evaluated first,
    so later duplicates are never reached. These should be consolidated or removed.
    """
    findings = []

    policies = vdom.get("firewall", {}).get("policy", []) or []

    # Build a signature for each policy: (srcaddr, dstaddr, service, action)
    signatures = {}  # signature -> [policy_id, ...]

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            srcaddr = _normalize_field(policy_data.get("srcaddr"))
            dstaddr = _normalize_field(policy_data.get("dstaddr"))
            service = _normalize_field(policy_data.get("service"))
            action = policy_data.get("action", "").lower()

            signature = (srcaddr, dstaddr, service, action)
            if signature not in signatures:
                signatures[signature] = []
            signatures[signature].append((policy_id, policy_data.get("name", f"Policy {policy_id}")))

    # Find duplicates
    duplicates = [(sig, ids) for sig, ids in signatures.items() if len(ids) > 1]

    if not duplicates:
        return []

    findings.append(
        (
            "### Redundant / duplicate firewall rules detected\n\n"
            "Multiple policies with identical source, destination, and service conditions "
            "are redundant. The first matching rule will be evaluated; later duplicates are "
            "never reached. These rules should be consolidated or removed to reduce clutter "
            "and improve maintainability.\n"
        )
    )

    for sig, policy_list in duplicates:
        srcaddr, dstaddr, service, action = sig
        src_str = " + ".join(srcaddr) if srcaddr else "any"
        dst_str = " + ".join(dstaddr) if dstaddr else "any"
        svc_str = " + ".join(service) if service else "any"

        findings.append(f"* **{src_str}** → **{dst_str}** / **{svc_str}** [{action}]:")

        for policy_id, policy_name in policy_list:
            findings.append(f"  - Policy **{policy_id}** ({policy_name})")

        findings.append("")

    return findings
