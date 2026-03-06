SECTION = "4_vpns"
TITLE = "Weak crypto (3des, sha1, DH<14, short keylife, PFS disabled)"


def run(vdom):
    """Detect weak crypto settings in VPN configuration."""

    findings = []

    # ------------------------------
    # IPsec Phase1 (interface-based)
    # ------------------------------
    phase1 = vdom.get("vpn", {}).get("ipsec_phase1-interface", [])

    for entry in phase1:
        if not isinstance(entry, dict):
            continue
        for name, obj in entry.items():
            if not isinstance(obj, dict):
                continue

            proposals = obj.get("proposal", "")

            if proposals:
                proposal_items = proposals.split()

                for suite in proposal_items:
                    # detect 3des or sha1 inside proposal entry
                    if "3des" in suite.lower():
                        findings.append(
                            f"* **{name}**: uses weak encryption (`{suite}`)"
                        )
                    if "sha1" in suite.lower() and not suite.lower().endswith("sha256"):
                        findings.append(
                            f"* **{name}**: uses weak hash (`{suite}`)"
                        )

            # DH group
            dhgrp = obj.get("dhgrp")
            if isinstance(dhgrp, int) and dhgrp < 14:
                findings.append(
                    f"* **{name}**: weak DH group `{dhgrp}` (<14)"
                )

            # Key lifetime
            lifetime = obj.get("keylife")
            if lifetime == 3600:
                findings.append(
                    f"* **{name}**: short keylife `{lifetime}s`"
                )

    # ------------------------------
    # IPsec Phase2 (selectors)
    # ------------------------------
    phase2 = vdom.get("vpn", {}).get("ipsec_phase2-interface", [])

    for entry in phase2:
        if not isinstance(entry, dict):
            continue
        for name, obj in entry.items():
            if not isinstance(obj, dict):
                continue

            pfs = obj.get("pfs", "")
            if pfs == "disable":
                findings.append(
                    f"* **{name}**: PFS disabled"
                )

            lifetime = obj.get("keylifeseconds")
            if lifetime == 3600:
                findings.append(
                    f"* **{name}**: short Phase2 keylife `{lifetime}s`"
                )

    # ------------------------------
    # SSL‑VPN
    # ------------------------------
    sslvpn = vdom.get("vpn", {}).get("ssl_settings", {})

    if sslvpn:
        # weak algorithms
        if sslvpn.get("algorithm") in ("3des-sha1", "sha1"):
            findings.append(
                f"* **SSL‑VPN**: weak crypto `{sslvpn.get('algorithm')}`"
            )

        # DH bit-length
        dh = sslvpn.get("dh-bits")
        if dh and dh < 2048:
            findings.append(
                f"* **SSL‑VPN**: DH parameter `{dh}` bits (<2048)"
            )

    # ------------------------------
    # Format findings as Markdown
    # ------------------------------

    if not findings:
        return []  # section aggregator will handle

    header = (
        "### Weak crypto (3des, sha1, DH<14, short keylife, PFS disabled)\n\n"
        "The VPN configuration uses deprecated or weak cryptographic settings that "
        "do not meet modern security requirements. These weaknesses lower resistance "
        "to brute‑force attacks, downgrade attacks, and interception.\n\n"
    )

    md = [header]
    md.extend(findings)
    md.append("")  # Final newline

    return md