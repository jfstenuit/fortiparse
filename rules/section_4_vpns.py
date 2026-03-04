SECTION = "4_vpns"
TITLE = "Virtual Private Networks (VPN) security gaps"


def render(findings):
    """Return Markdown for this section only if there are findings."""
    if not findings:
        return ""

    intro = (
        "This section reviews the configuration of all IPsec and SSL VPN tunnels "
        "and highlights weaknesses that may expose the organisation to interception, "
        "downgrade attacks, credential compromise, or traffic manipulation.\n\n"
        "Misconfigurations typically include:\n"
        "- usage of deprecated cryptographic algorithms (e.g., 3DES, SHA1)\n"
        "- weak Diffie-Hellman groups (<14)\n"
        "- short key lifetimes\n"
        "- disabled PFS (Perfect Forward Secrecy)\n"
        "- permissive or reused pre‑shared keys\n\n"
        "These gaps can significantly reduce confidentiality and integrity of "
        "inter‑site or remote‑access VPN communications."
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