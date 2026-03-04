SECTION = "1_objects"
TITLE = "Issues with objects (addresses, services, groups)"


def render(findings):
    """Return Markdown for this section only if there are findings."""
    if not findings:
        return ""

    intro = (
        "Firewall objects (addresses, services, and groups) form the building blocks of "
        "security policies. Poor object management leads to configuration confusion, policy "
        "misinterpretation, operational bloat, and maintenance overhead. This section audits "
        "objects for redundancy, naming inconsistency, overly broad definitions, and unused entries. "
        "Addressing these issues improves policy clarity, reduces misconfiguration risk, and "
        "streamlines maintenance efforts."
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