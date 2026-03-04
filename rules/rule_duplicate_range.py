SECTION = "1_objects"
TITLE = "Duplicate IP range objects"


def run(vdom):
    """Detect address objects that define identical IP ranges.

    FortiGate range objects typically use `type: "iprange"` with `start-ip`
    and `end-ip` (IPv4) or IPv6 equivalents. This rule finds objects that
    represent exactly the same start/end pair and reports duplicates.
    """

    findings = []

    addrs = vdom.get("firewall", {}).get("address", []) or []

    seen = {}  # mapping range_signature -> [object names]

    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue

            # prefer explicit iprange type, but also accept presence of both keys
            start = obj_data.get("start-ip") or obj_data.get("start-ip6")
            end = obj_data.get("end-ip") or obj_data.get("end-ip6")
            obj_type = obj_data.get("type", "")

            if obj_type != "iprange" and (not start or not end):
                # not a range-like object
                continue

            # normalize signature as "start-end"
            signature = f"{start} - {end}"
            seen.setdefault(signature, []).append(obj_name)

    duplicates = [(sig, names) for sig, names in seen.items() if len(names) > 1]

    if not duplicates:
        return []

    findings.append(
        (
            "### Duplicate IP ranges in address objects\n\n"
            "Multiple address objects define the same start/end IP pair.\n"
            "This is redundant and may cause confusion when referencing these objects\n"
            "in policies. Consider consolidating them.\n"
        )
    )

    for sig, names in duplicates:
        findings.append(f"* **{sig}** used in: {', '.join(names)}")

    findings.append("")
    return findings
