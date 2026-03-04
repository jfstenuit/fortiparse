SECTION = "1_objects"
TITLE = "Oversized groups mixing unrelated members"

SIZE_THRESHOLD = 10  # Flag groups with more than this many members


def _infer_member_type(member_name, addresses, address_groups, services, service_groups):
    """Try to infer the type of a member by looking it up in known lists."""
    # Check if it's an address
    for addr_entry in addresses:
        if isinstance(addr_entry, dict):
            for name, data in addr_entry.items():
                if name == member_name:
                    if isinstance(data, dict):
                        addr_type = data.get("type", "subnet")
                        if addr_type == "fqdn":
                            return "fqdn"
                        elif addr_type == "iprange":
                            return "iprange"
                        elif "subnet" in data:
                            return "subnet"
                        else:
                            return "address"
                    return "address"

    # Check if it's an address group
    for grp_entry in address_groups:
        if isinstance(grp_entry, dict):
            for name in grp_entry.keys():
                if name == member_name:
                    return "address_group"

    # Check if it's a service
    for svc_entry in services:
        if isinstance(svc_entry, dict):
            for name in svc_entry.keys():
                if name == member_name:
                    return "service"

    # Check if it's a service group
    for grp_entry in service_groups:
        if isinstance(grp_entry, dict):
            for name in grp_entry.keys():
                if name == member_name:
                    return "service_group"

    # Default: unknown
    return "unknown"


def run(vdom):
    """Detect address and service groups that are oversized and mix unrelated members.

    Large groups (>10 members) that contain fundamentally different object types
    (e.g., IP subnets mixed with FQDNs, or addresses mixed with services) indicate
    poor structure and may complicate maintenance. This rule flags such groups.
    """
    findings = []

    fw = vdom.get("firewall", {})
    addresses = fw.get("address", []) or []
    address_groups = fw.get("addrgrp", []) or []
    services = fw.get("service_custom", []) or []
    service_groups = fw.get("service_group", []) or []

    oversized_mixed = []

    # Check address groups
    for grp_entry in address_groups:
        if not isinstance(grp_entry, dict):
            continue
        for grp_name, grp_data in grp_entry.items():
            if not isinstance(grp_data, dict):
                continue

            members = grp_data.get("member", [])
            if not isinstance(members, list):
                members = [members] if members else []

            if len(members) <= SIZE_THRESHOLD:
                continue

            # Infer member types
            member_types = set()
            for member in members:
                mtype = _infer_member_type(member, addresses, address_groups, services, service_groups)
                member_types.add(mtype)

            # Check if mixed: if we have more than one fundamental type (subnet vs fqdn vs service, etc.)
            # Simplification: flag if there are services in an address group, or multiple address types
            has_service = any(t.startswith("service") for t in member_types)
            address_types = [t for t in member_types if not t.startswith("service") and t != "unknown"]
            has_multiple_address_types = len(address_types) > 1

            is_mixed = has_service or has_multiple_address_types

            if is_mixed:
                type_summary = ", ".join(sorted(member_types))
                oversized_mixed.append((grp_name, len(members), type_summary, "address"))

    # Check service groups
    for grp_entry in service_groups:
        if not isinstance(grp_entry, dict):
            continue
        for grp_name, grp_data in grp_entry.items():
            if not isinstance(grp_data, dict):
                continue

            members = grp_data.get("member", [])
            if not isinstance(members, list):
                members = [members] if members else []

            if len(members) <= SIZE_THRESHOLD:
                continue

            # Service groups should only contain services; if mixed with addresses it's bad
            member_types = set()
            for member in members:
                mtype = _infer_member_type(member, addresses, address_groups, services, service_groups)
                member_types.add(mtype)

            has_address = any(not t.startswith("service") and t != "unknown" for t in member_types)

            if has_address:
                type_summary = ", ".join(sorted(member_types))
                oversized_mixed.append((grp_name, len(members), type_summary, "service"))

    if not oversized_mixed:
        return []

    findings.append(
        (
            "### Oversized groups mixing unrelated members\n\n"
            f"Groups with more than {SIZE_THRESHOLD} members that contain mixed or unrelated types "
            "(e.g., IP addresses + FQDNs, or addresses + services) indicate poor structure "
            "and complicate maintenance and policy review.\n"
        )
    )

    for grp_name, member_count, type_summary, grp_type in oversized_mixed:
        findings.append(
            f"* **{grp_name}** ({grp_type} group): {member_count} members, types: {type_summary}"
        )

    findings.append("")
    return findings
