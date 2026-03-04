SECTION = "1_objects"
TITLE = "Unused firewall objects"


def run(vdom):
    """Detect address and service objects that are never referenced in policies.

    Unused objects clutter the configuration and increase the maintenance burden.
    This rule identifies objects that do not appear in any firewall policy
    (srcaddr, dstaddr, or service fields).
    """
    findings = []

    fw = vdom.get("firewall", {})
    addresses = fw.get("address", []) or []
    address_groups = fw.get("addrgrp", []) or []
    services = fw.get("service_custom", []) or []
    service_groups = fw.get("service_group", []) or []
    policies = fw.get("policy", []) or []

    # Collect all object names
    all_address_names = set()
    for obj_entry in addresses + address_groups:
        if isinstance(obj_entry, dict):
            for name in obj_entry.keys():
                all_address_names.add(name)

    all_service_names = set()
    for obj_entry in services + service_groups:
        if isinstance(obj_entry, dict):
            for name in obj_entry.keys():
                all_service_names.add(name)

    # Collect all referenced names from policies
    referenced = set()

    for policy_entry in policies:
        if not isinstance(policy_entry, dict):
            continue
        for policy_id, policy_data in policy_entry.items():
            if not isinstance(policy_data, dict):
                continue

            # Scan srcaddr, dstaddr fields for address references
            for field in ["srcaddr", "dstaddr"]:
                val = policy_data.get(field)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            referenced.add(item)
                elif isinstance(val, str):
                    referenced.add(val)

            # Scan service field for service references
            svc_val = policy_data.get("service")
            if isinstance(svc_val, list):
                for item in svc_val:
                    if isinstance(item, str):
                        referenced.add(item)
            elif isinstance(svc_val, str):
                referenced.add(svc_val)

    # Find unused addresses and services
    unused_addresses = sorted(all_address_names - referenced)
    unused_services = sorted(all_service_names - referenced)

    # Filter out special/built-in ones like "all", "none" that are always implicitly used
    builtin_names = {"all", "none", "ANY"}
    unused_addresses = [a for a in unused_addresses if a.lower() not in builtin_names]
    unused_services = [s for s in unused_services if s.lower() not in builtin_names]

    if not unused_addresses and not unused_services:
        return []

    findings.append(
        (
            "### Unused firewall objects\n\n"
            "Address and service objects that are not referenced in any firewall policy "
            "should be reviewed and removed if they are no longer needed. Unused objects "
            "clutter the configuration and increase maintenance burden.\n"
        )
    )

    if unused_addresses:
        findings.append(f"**Unused address objects ({len(unused_addresses)}):**\n")
        for addr in unused_addresses[:20]:  # Show up to 20
            findings.append(f"* {addr}")
        if len(unused_addresses) > 20:
            findings.append(f"* ... and {len(unused_addresses) - 20} more\n")

    if unused_services:
        findings.append(f"\n**Unused service objects ({len(unused_services)}):**\n")
        for svc in unused_services[:20]:  # Show up to 20
            findings.append(f"* {svc}")
        if len(unused_services) > 20:
            findings.append(f"* ... and {len(unused_services) - 20} more\n")

    findings.append("")
    return findings
