SECTION = "2_policies"
TITLE = "Firewall policy anti-patterns and inefficiencies"


def render(findings):
    """Return Markdown for this section only if there are findings."""
    if not findings:
        return ""

    intro = (
        "Firewall policies are the core of network access control. Issues in policy "
        "configuration directly impact security posture, performance, and maintainability. "
        "This section audits policies for common anti-patterns including overly permissive "
        "rules, redundant rules, disabled rules that clutter the ruleset, and misconfigurations "
        "in NAT and load balancing. Fixing these issues reduces attack surface, improves "
        "rule clarity, and eases operational maintenance."
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
