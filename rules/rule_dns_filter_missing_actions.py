SECTION = "3_utm"
TITLE = "DNS filter entries missing explicit actions"


def _gather_dns_profiles(vdom):
    # Common keys where dnsfilter profiles may live
    df = vdom.get("dnsfilter", {}) or {}
    for key in ("profile", "dnsfilter-profile", "dnsfilter_profile", "profile-list"):
        val = df.get(key)
        if val:
            return val
    # Fallback to top-level
    return vdom.get("dnsfilter_profile", []) or vdom.get("dnsfilter-profile", []) or []


def _iter_profile_entries(profile_data):
    # Yield (section_name, entry_id, entry_data) for list/dict children
    if not isinstance(profile_data, dict):
        return
    for key, val in profile_data.items():
        # skip metadata
        if key in {"comment", "name", "uuid", "range"}:
            continue
        if isinstance(val, list):
            for entry in val:
                if isinstance(entry, dict):
                    for eid, ed in entry.items():
                        yield key, eid, ed
        elif isinstance(val, dict):
            for eid, ed in val.items():
                yield key, eid, ed


def run(vdom):
    """Detect DNS filter profiles or rules that are missing explicit action fields.

    DNS filter profiles should explicitly define actions for filter entries and a
    clear default action. Missing actions may lead to ambiguous behaviour or
    default permissive handling by the device. This rule flags profiles where
    entries lack an `action` (or equivalent) field or where the profile lacks
    a documented default action.
    """
    findings = []

    profiles = _gather_dns_profiles(vdom)
    if not profiles:
        return []

    broken = []

    for entry in profiles:
        if not isinstance(entry, dict):
            continue
        for profile_name, profile_data in entry.items():
            if not isinstance(profile_data, dict):
                continue

            issues = []

            # Check for missing default action
            default_action = (profile_data.get("default-action") or profile_data.get("default_action"))
            if not default_action:
                issues.append("missing default-action on profile")
            else:
                if str(default_action).lower() in {"allow", "permit", "bypass", "monitor"}:
                    issues.append(f"default-action is '{default_action}' (permissive)")

            # Inspect child entries for missing action keys
            missing_actions = []
            permissive_entries = []
            for section, eid, ed in _iter_profile_entries(profile_data):
                if not isinstance(ed, dict):
                    continue
                # action may be named 'action', 'policy', or 'type'
                if not any(k in ed for k in ("action", "policy", "type")):
                    missing_actions.append(f"{section}:{eid}")
                else:
                    act = ed.get("action") or ed.get("policy") or ed.get("type")
                    if act and str(act).lower() in {"allow", "permit", "monitor", "warning"}:
                        permissive_entries.append(f"{section}:{eid}")

            if missing_actions:
                sample = missing_actions[:8]
                issues.append(f"{len(missing_actions)} entries missing action (examples: {', '.join(sample)})")
            if permissive_entries:
                samplep = permissive_entries[:6]
                issues.append(f"entries explicitly permissive (examples: {', '.join(samplep)})")

            if issues:
                broken.append((profile_name, issues))

    if not broken:
        return []

    findings.append(
        (
            "### DNS filter profiles with missing or permissive actions\n\n"
            "DNS filter profiles should define explicit actions for each filter entry and a clear, "
            "conservative default action. Missing action fields can lead to ambiguous or permissive "
            "behaviour. Profiles flagged here should be reviewed and updated to explicitly define "
            "actions and ensure non-whitelisted traffic is blocked or logged.\n"
        )
    )

    for profile_name, issues in broken:
        findings.append(f"* **{profile_name}**: {'; '.join(issues)}")

    findings.append("")
    return findings
