SECTION = "3_utm"
TITLE = "Webfilter categories configured to fail-open"


def _gather_profiles(vdom):
    # Try common locations for webfilter profile lists
    wf = vdom.get("webfilter", {}) or {}
    candidates = []
    for key in ("profile", "webfilter-profile", "webfilter_profile", "webfilter-profile-list"):
        val = wf.get(key)
        if val:
            candidates = val
            break
    # Fallback: top-level key
    if not candidates:
        candidates = vdom.get("webfilter_profile", []) or vdom.get("webfilter-profile", []) or []
    return candidates or []


def _get_default_action(profile_data):
    # Check several possible places for default action
    if not isinstance(profile_data, dict):
        return None
    da = profile_data.get("default-action") or profile_data.get("default_action")
    if da:
        return da.lower()
    # urlfilter default-action
    urlf = profile_data.get("urlfilter", {})
    if isinstance(urlf, dict):
        da = urlf.get("default-action") or urlf.get("default_action")
        if da:
            return da.lower()
    return None


def _collect_category_allows(profile_data):
    allows = []
    # categories may be under 'category' or 'categories'
    for key in ("category", "categories", "web"):
        entries = profile_data.get(key, [])
        if not entries:
            continue
        if isinstance(entries, list):
            for e in entries:
                if not isinstance(e, dict):
                    continue
                # entries often are {"<id>": {"action": "allow"}}
                for _, ed in e.items():
                    if not isinstance(ed, dict):
                        continue
                    action = ed.get("action") or ed.get("policy")
                    if action and str(action).lower() in {"allow", "monitor", "warning"}:
                        # try to get a readable id/name
                        cat_name = ed.get("name") or ed.get("category") or ed.get("id")
                        allows.append(str(cat_name) if cat_name else "(unnamed)")
    return allows


def run(vdom):
    """Detect webfilter profiles that may 'fail-open' categories or default to allow.

    A 'fail-open' webfilter profile is one where, on category lookup failures or by
    default, traffic is permitted rather than blocked or inspected. This rule looks
    for profiles with permissive default actions and category entries explicitly set
    to permissive values (e.g., `allow`, `monitor`, or `warning`).
    """
    findings = []

    profiles = _gather_profiles(vdom)
    if not profiles:
        return []

    flagged = []
    for entry in profiles:
        if not isinstance(entry, dict):
            continue
        for profile_name, profile_data in entry.items():
            if not isinstance(profile_data, dict):
                continue

            issues = []
            default_action = _get_default_action(profile_data)
            if default_action in {"allow", "monitor", "warning"}:
                issues.append(f"default-action is '{default_action}' (may be fail-open)")

            allowed_categories = _collect_category_allows(profile_data)
            if allowed_categories:
                sample = allowed_categories[:5]
                issues.append(f"categories explicitly allow/monitor: {', '.join(sample)}")

            # Check for policy that allows uncategorized/unknown as allow
            uncategorized = profile_data.get("uncategorized") or profile_data.get("unknown-category") or {}
            if isinstance(uncategorized, dict):
                ua = uncategorized.get("action") or uncategorized.get("default-action")
                if ua and str(ua).lower() in {"allow", "monitor"}:
                    issues.append(f"uncategorized/unknown category action '{ua}'")

            if issues:
                flagged.append((profile_name, issues))

    if not flagged:
        return []

    findings.append(
        (
            "### Webfilter profiles with categories that may fail-open\n\n"
            "Webfilter profiles should fail-closed for unknown or uncategorized sites and avoid "
            "explicitly allowing risky categories. Profiles with permissive default actions or "
            "category entries set to allow/monitor reduce protection and should be reviewed.\n"
        )
    )

    for profile_name, issues in flagged:
        findings.append(f"* **{profile_name}**: {'; '.join(issues)}")

    findings.append("")
    return findings
