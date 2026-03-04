SECTION = "3_utm"
TITLE = "Replay detection disabled in IPS/UTM sensors"


def _is_disabled_value(v):
    if v is None:
        return False
    if isinstance(v, bool):
        return v is False
    sval = str(v).lower()
    return sval in {"disable", "disabled", "off", "0", "false"}


def _search_replay(obj, path=None, results=None):
    """Recursively search object for keys related to replay detection being disabled.

    Returns list of (path, value) hits where the value indicates disabled.
    """
    if results is None:
        results = []
    if path is None:
        path = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            new_path = path + [str(k)]
            # keys that indicate replay detection settings
            if "replay" in lk or "replay-detect" in lk or "replay-detection" in lk:
                if _is_disabled_value(v):
                    results.append((".".join(new_path), v))
            # if value is dict or list, recurse
            if isinstance(v, (dict, list)):
                _search_replay(v, new_path, results)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _search_replay(item, path + [f"[{idx}]"], results)

    return results


def run(vdom):
    """Detect IPS/UTM entries where replay detection is explicitly disabled.

    Replay detection (anti-replay) helps prevent replay attacks against stateful
    inspection and intrusion prevention logic. Profiles or sensors that explicitly
    disable replay detection should be reviewed.
    """
    findings = []

    # Search common UTM/IPS locations first
    candidates = []
    candidates.extend(vdom.get("ips", {}).get("sensor", []) or [])
    candidates.extend(vdom.get("ips_sensor", []) or [])
    candidates.extend(vdom.get("ips-sensor", []) or [])
    candidates.extend(vdom.get("firewall", {}).get("ssl-ssh-profile", []) or [])

    # Also perform a global search over the vdom for replay-related keys
    global_hits = _search_replay(vdom)

    hits = []

    # Search the candidate lists more specifically
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        for name, data in entry.items():
            found = _search_replay(data, path=[name])
            for p, val in found:
                hits.append((name, p, val))

    # Add global hits that are outside the above candidates (avoid duplicates)
    for p, val in global_hits:
        # try to extract a top-level name from path
        top = p.split(".")[0]
        if not any(top == h[0] for h in hits):
            hits.append((top, p, val))

    if not hits:
        return []

    findings.append(
        (
            "### Replay detection disabled detected\n\n"
            "Replay detection (anti-replay) helps prevent replay-based attacks and is an important "
            "component of reliable IPS/UTM inspection. Configuration entries that explicitly disable "
            "replay detection should be reviewed to ensure there is a compensating control or a valid justification.\n"
        )
    )

    for name, path, val in hits:
        findings.append(f"* **{name}** — `{path}`: set to '{val}' (disabled)")

    findings.append("")
    return findings
