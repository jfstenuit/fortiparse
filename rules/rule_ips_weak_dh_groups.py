SECTION = "3_utm"
TITLE = "IPS sensors using weak Diffie-Hellman (DH) groups"

WEAK_DH_THRESHOLD = 14  # DH groups with number < 14 considered weak


def _is_numeric(val):
    try:
        return int(val)
    except Exception:
        return None


def _search_for_dh(obj, path=None, results=None):
    """Recursively search for keys suggesting DH group configuration.

    Returns list of tuples (path, value) where value is numeric or string numeric.
    """
    if results is None:
        results = []
    if path is None:
        path = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            new_path = path + [str(k)]
            # key patterns that may indicate DH group
            if "dh" in lk and "group" in lk or lk in {"dh", "dh-group", "dh_group", "dhgroup"}:
                num = _is_numeric(v)
                if num is not None:
                    results.append((".".join(new_path), num))
            # also check values that are dict/list
            _search_for_dh(v, new_path, results)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _search_for_dh(item, path + [f"[{idx}]"], results)
    return results


def run(vdom):
    """Detect IPS-related configuration entries that specify weak DH groups.

    This rule searches IPS sensors and other UTM-related structures for keys
    that indicate DH group settings. Group numbers below `WEAK_DH_THRESHOLD`
    (e.g. < 14) are considered weak and flagged for review.
    """
    findings = []

    # Candidate places to look for IPS and UTM sensor definitions
    ips_candidates = []
    ips_candidates.extend(vdom.get("ips", {}).get("sensor", []) or [])
    ips_candidates.extend(vdom.get("ips_sensor", []) or [])
    ips_candidates.extend(vdom.get("ips-sensor", []) or [])

    # Also check ssl profiles and vpn profiles as DH params may be present there
    ssl_profiles = vdom.get("firewall", {}).get("ssl-ssh-profile", []) or []
    vpn_phase1 = vdom.get("vpn", {}).get("ipsec", {}).get("phase1", []) if isinstance(vdom.get("vpn", {}), dict) else []

    weak_found = []

    # scan IPS candidates
    for entry in ips_candidates:
        if not isinstance(entry, dict):
            continue
        for name, data in entry.items():
            dhs = _search_for_dh(data, path=[name])
            for p, val in dhs:
                if val < WEAK_DH_THRESHOLD:
                    weak_found.append((name, p, val))

    # scan SSL profiles
    for entry in ssl_profiles:
        if not isinstance(entry, dict):
            continue
        for name, data in entry.items():
            dhs = _search_for_dh(data, path=[name])
            for p, val in dhs:
                if val < WEAK_DH_THRESHOLD:
                    weak_found.append((name, p, val))

    # scan vpn phase1 entries if present
    if isinstance(vpn_phase1, list):
        for entry in vpn_phase1:
            if not isinstance(entry, dict):
                continue
            for name, data in entry.items():
                dhs = _search_for_dh(data, path=[name])
                for p, val in dhs:
                    if val < WEAK_DH_THRESHOLD:
                        weak_found.append((name, p, val))

    if not weak_found:
        return []

    findings.append(
        (
            "### IPS / UTM entries using weak Diffie-Hellman groups\n\n"
            "Diffie-Hellman (DH) groups with small group numbers correspond to weaker key sizes. "
            "Using DH groups below {threshold} (e.g., group 1/2/5) is considered weak and may "
            "expose the appliance to cryptographic attacks. Review and migrate to stronger DH "
            "groups (>= {threshold}).\n"
        ).format(threshold=WEAK_DH_THRESHOLD)
    )

    # Report findings
    for name, path, val in weak_found:
        findings.append(f"* **{name}** — `{path}`: DH group {val} (< {WEAK_DH_THRESHOLD})")

    findings.append("")
    return findings
