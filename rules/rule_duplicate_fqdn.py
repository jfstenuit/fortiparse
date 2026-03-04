SECTION = "1_objects"
TITLE = "Duplicate FQDN objects"


def _normalize(fqdn):
    if not fqdn:
        return ""
    # lower-case and strip trailing dot
    return fqdn.lower().rstrip('.')


def run(vdom):
    """Detect firewall address objects that reference the same FQDN.

    This rule inspects objects of `type: fqdn` and reports identical FQDN
    values used by multiple objects (case-insensitive).
    """

    findings = []

    addrs = vdom.get("firewall", {}).get("address", []) or []

    seen = {}  # mapping normalized fqdn -> [object names]

    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue

            if obj_data.get("type") != "fqdn":
                continue

            fq = _normalize(obj_data.get("fqdn") or "")
            if not fq:
                continue

            seen.setdefault(fq, []).append(obj_name)

    duplicates = [(fq, names) for fq, names in seen.items() if len(names) > 1]

    if not duplicates:
        return []

    findings.append(
        (
            "### Duplicate FQDN values in address objects\n\n"
            "Multiple address objects reference the same FQDN value.  This is redundant\n"
            "and may be confusing when used in policies—consider consolidation.\n"
        )
    )

    for fq, names in duplicates:
        findings.append(f"* **{fq}** used in: {', '.join(names)}")

    findings.append("")
    return findings
