SECTION = "1_objects"
TITLE = "Host /32 address explosion"


def run(vdom):
    """Detect excessive proliferation of host (/32) address objects.

    When administrators create one address object per host instead of using
    larger subnets or groups, it leads to configuration bloat and maintenance
    burden. This rule counts /32 (255.255.255.255) address objects and flags
    if the count exceeds a threshold (>20).
    """
    findings = []

    addrs = vdom.get("firewall", {}).get("address", []) or []

    hosts_32 = []

    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue

            # check for /32 mask in subnet field
            subnet = obj_data.get("subnet", "")
            if subnet and "255.255.255.255" in subnet:
                hosts_32.append(obj_name)

    if len(hosts_32) <= 20:
        return []

    # Report explosion of /32 objects
    findings.append(
        (
            f"### Host (/32) address objects explosion\n\n"
            f"Found {len(hosts_32)} host (/32) address objects. This is excessive and suggests "
            f"that the configuration would benefit from using address groups, "
            f"dynamic objects, or broader subnets to reduce maintenance burden.\n"
        )
    )

    # Show first 10 as examples
    for name in hosts_32[:10]:
        findings.append(f"* {name}")

    if len(hosts_32) > 10:
        findings.append(f"* ... and {len(hosts_32) - 10} more")

    findings.append("")
    return findings
