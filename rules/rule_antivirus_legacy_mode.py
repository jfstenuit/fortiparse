SECTION = "3_utm"
TITLE = "Antivirus profiles using legacy mode or weak engines"

# If engine-version is present and <= this value, flag it as legacy/weak
ENGINE_LEGACY_THRESHOLD = 8


def _gather_av_profiles(vdom):
    av = vdom.get("antivirus", {}) or {}
    for key in ("profile", "antivirus-profile", "antivirus_profile", "profiles"):
        val = av.get(key)
        if val:
            return val
    # fallback top-level
    return vdom.get("antivirus_profile", []) or vdom.get("antivirus-profile", []) or []


def _is_legacy_profile(name, pdata):
    # name or comments with legacy/deprecated keywords
    if isinstance(name, str) and ("legacy" in name.lower() or "deprecated" in name.lower() or "old-" in name.lower()):
        return True
    comment = pdata.get("comment", "") or pdata.get("comments", "")
    if isinstance(comment, str) and ("legacy" in comment.lower() or "deprecated" in comment.lower()):
        return True

    # explicit flags
    if pdata.get("legacy-mode") or pdata.get("legacy_mode") or pdata.get("antivirus-legacy"):
        return True

    mode = pdata.get("mode") or pdata.get("scan-mode") or pdata.get("scan_mode")
    if isinstance(mode, str) and "legacy" in mode.lower():
        return True

    # engine-version numeric check
    ev = pdata.get("engine-version") or pdata.get("engine_version") or pdata.get("engine")
    try:
        if ev is not None:
            evn = int(ev)
            if evn <= ENGINE_LEGACY_THRESHOLD:
                return True
    except Exception:
        pass

    return False


def _extract_engine_info(pdata):
    ev = pdata.get("engine-version") or pdata.get("engine_version") or pdata.get("engine")
    return ev


def run(vdom):
    """Detect antivirus profiles that use legacy modes or weak engine versions.

    Legacy antivirus modes or old engine versions can miss modern malware and
    significantly reduce detection efficacy. This rule identifies profiles that
    explicitly mention legacy behavior or include low engine-version values.
    """
    findings = []

    profiles = _gather_av_profiles(vdom)
    if not profiles:
        return []

    flagged = []
    for entry in profiles:
        if not isinstance(entry, dict):
            continue
        for profile_name, pdata in entry.items():
            if not isinstance(pdata, dict):
                continue
            issues = []
            if _is_legacy_profile(profile_name, pdata):
                issues.append("profile indicates legacy mode or deprecated settings")
            ev = _extract_engine_info(pdata)
            try:
                if ev is not None:
                    evn = int(ev)
                    if evn <= ENGINE_LEGACY_THRESHOLD:
                        issues.append(f"engine-version {evn} (<= {ENGINE_LEGACY_THRESHOLD})")
            except Exception:
                # non-numeric engine info - if it contains 'legacy' flag, already caught
                pass

            if issues:
                flagged.append((profile_name, issues))

    if not flagged:
        return []

    findings.append(
        (
            "### Antivirus profiles in legacy mode or with weak engines\n\n"
            "Antivirus profiles that use legacy scanning modes or older engine versions can miss "
            "modern threats. Review flagged profiles and update to current scanning modes and engines.\n"
        )
    )

    for name, issues in flagged:
        findings.append(f"* **{name}**: {'; '.join(issues)}")

    findings.append("")
    return findings
