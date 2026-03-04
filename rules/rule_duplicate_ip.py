SECTION = "1_objects"
TITLE = "Duplicate IP address objects"


def run(vdom):
    """Detect address objects that define the same IP/Subnet (IPv4 or IPv6).

    The FortiGate configuration often contains many address objects, and
    administrators occasionally create two or more objects that resolve to
    exactly the same IP value.  Those duplicates are confusing and can
    introduce maintenance issues.  This rule looks for identical values in
    the `subnet` (IPv4) or `ip6` (IPv6) properties of address objects and
    reports any collisions.
    """

    findings = []

    # combine IPv4 and IPv6 address lists if they exist
    addrs_v4 = vdom.get("firewall", {}).get("address", []) or []
    addrs_v6 = vdom.get("firewall", {}).get("address6", []) or []
    all_addrs = addrs_v4 + addrs_v6

    seen = {}  # mapping value -> [object names]

    for entry in all_addrs:
        if not isinstance(entry, dict):
            continue

        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue

            # look for the common IP properties
            ipval = obj_data.get("subnet") or obj_data.get("ip6")
            if not ipval:
                continue

            seen.setdefault(ipval, []).append(obj_name)

    duplicates = [(val, names) for val, names in seen.items() if len(names) > 1]

    if not duplicates:
        return []

    # format markdown findings
    # use a single multi-line literal for clarity
    findings.append(
        (
            "### Duplicate IP/Subnet values in address objects\n\n"
            "Multiple address objects resolve to the same IP or subnet.  Having "
            "duplicates is redundant and may lead to confusion when writing "
            "policies.  Consider consolidating or renaming these objects.\n"
        )
    )

    for val, names in duplicates:
        findings.append(f"* **{val}** used in: {', '.join(names)}")

    findings.append("")  # trailing newline
    return findings
