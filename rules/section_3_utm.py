SECTION = "3_utm"
TITLE = "Unified Threat Management (UTM) security gaps"


def render(findings):
    """Return Markdown for this section only if there are findings."""
    if not findings:
        return ""

    intro = (
        "Unified Threat Management (UTM) features protect against advanced threats including "
        "malware, intrusions, data exfiltration, and protocol-based attacks. UTM includes SSL "
        "inspection, web filtering, DNS filtering, intrusion prevention, antivirus, and other "
        "security appliance functions. Misconfigurations in UTM—such as disabled inspection, "
        "excessive exemptions, weak DH parameters, or fail-open behavior—significantly degrade "
        "security effectiveness. This section audits UTM policies and settings to identify gaps "
        "that weaken threat detection and prevention."
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
