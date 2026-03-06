SECTION = "5_management"
TITLE = "SNMP DES and weak SNMP security"


def run(vdom):
    """
    Detect SNMPv3 DES usage, weak authentication (MD5), or unsafe SNMP community settings.
    This module is specifically tailored to the JSON structure provided by the user.
    """

    findings = []

    # ================================
    # SNMP v3 Users (strongest signals)
    # ================================
    snmp_users = vdom.get("system", {}).get("snmp_user", [])

    for entry in snmp_users:
        # Each entry is a dict with a single SNMP user
        for username, user in entry.items():

            priv = user.get("priv-proto", "").lower()
            auth = user.get("auth-proto", "").lower()

            # DES is insecure for SNMP privacy
            if priv == "des":
                findings.append(
                    f"* **SNMP user `{username}`** uses weak privacy protocol `DES`"
                )

            # MD5 is weak for SNMP authentication
            if auth == "md5":
                findings.append(
                    f"* **SNMP user `{username}`** uses weak authentication protocol `MD5`"
                )

    # ================================
    # SNMP Communities (v1/v2c)
    # ================================
    snmp_communities = vdom.get("system", {}).get("snmp_community", [])

    for entry in snmp_communities:
        # Each entry is a dict with the community name as key
        for cname, comm in entry.items():

            # v1/v2c are legacy protocols lacking encryption
            version = comm.get("status") or comm.get("version")

            if version in ("v1", "v2c", "1", "2c"):
                findings.append(
                    f"* **SNMP community `{cname}`** uses insecure protocol `{version}`"
                )

            # Communities without ACL restrictors are dangerous
            hosts = comm.get("hosts", [])
            if not hosts or len(hosts) == 0:
                findings.append(
                    f"* **SNMP community `{cname}`** has no host restrictions (no ACL)"
                )

    # ================================
    # Final Markdown block
    # ================================
    if not findings:
        return []

    header = (
        "### SNMP DES and weak SNMP configuration\n\n"
        "The following SNMP configuration issues were detected. SNMPv3 DES provides no "
        "meaningful confidentiality, MD5 is deprecated for authentication, and SNMP v1/v2c "
        "lack encryption entirely. Missing ACLs may expose SNMP to untrusted networks.\n"
    )

    md = [header]
    md.extend(findings)
    md.append("")  # final newline

    return md