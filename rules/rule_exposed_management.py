SECTION = "5_management"
TITLE = "Exposed management interfaces"


def run(vdom):
    """
    Detect management protocols enabled on WAN-facing interfaces.
    'role': 'wan' is used as the authoritative indicator of an external interface.
    """

    findings = []
    interface_list = vdom.get("system", {}).get("interface", [])

    # Management services considered sensitive on external interfaces
    mgmt_keywords = {"https", "http", "ssh", "telnet", "snmp", "fgfm"}

    for entry in interface_list:
        # Each entry is a dict with a single key: interface name
        for ifname, iface in entry.items():

            # Only evaluate interfaces explicitly declared WAN
            if iface.get("role") != "wan":
                continue

            allow = iface.get("allowaccess", "")

            if not allow:
                continue  # no management services enabled => safe

            # Split allowaccess into its components:
            # "ping https ssh" => ["ping", "https", "ssh"]
            allow_set = {a.strip() for a in allow.split()}

            # Determine if any management service is exposed
            exposed = allow_set.intersection(mgmt_keywords)

            if exposed:
                # Construct a readable description
                exposed_list = ", ".join(sorted(exposed))
                ip_str = iface.get("ip", "<no IP>")

                findings.append(
                    f"* **{ifname}** (role=wan) exposes management access: "
                    f"`{exposed_list}` — IP: `{ip_str}`"
                )

    # No findings
    if not findings:
        return []

    # Markdown header + findings (module emits its own block)
    header = (
        "### Exposed management interfaces\n\n"
        "The following interfaces are marked as WAN-facing (`role: wan`) but allow "
        "remote administrative protocols. Exposing management services on untrusted "
        "networks significantly increases the risk of unauthorized access or device "
        "compromise.\n"
    )

    md = [header]
    md.extend(findings)
    md.append("")  # final newline

    return md