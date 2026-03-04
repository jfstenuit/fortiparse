SECTION = "5_management"
TITLE = "Management Interfaces, SNMP & Certificates"


def render(findings):
    """Return Markdown for this section only if there are findings."""
    if not findings:
        return ""

    intro = (
        "This section focuses on the exposure and security posture of management "
        "interfaces, SNMP settings, and device certificates. Misconfigurations in "
        "these areas often result in direct attack surface exposure, credential "
        "compromise, or downgrade vulnerabilities. Typical high‑risk issues include:\n\n"
        "- management access enabled on untrusted or WAN‑facing interfaces\n"
        "- weak or deprecated cryptographic certificates (RSA1024, DSA1024)\n"
        "- factory default Fortinet CA or self-signed device certificates still present\n"
        "- insecure SNMP configuration such as `priv-proto = DES`\n\n"
        "These weaknesses allow adversaries to interact with administrative services, "
        "bypass monitoring controls, or decrypt/impersonate encrypted management sessions."
    )

    md = [
        f"## **{TITLE}**\n",
        f"{intro}\n",
        "Below are all findings detected in this section:\n",
    ]

    for f in findings:
        md.append(f)

    md.append("")  # final newline
    return "\n".join(md)