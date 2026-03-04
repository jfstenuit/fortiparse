SECTION = "1_objects"
TITLE = "Broad service objects"


def run(vdom):
    """Detect service objects that represent overly permissive definitions.

    Services with names like "ALL", "ALL_TCP", "ALL_UDP" or those with
    protocol "IP" (all protocols) or very broad port ranges indicate that
    the policy is likely too permissive. This rule flags such broad services
    to encourage stricter, more specific service definitions.
    """
    findings = []

    services = vdom.get("firewall", {}).get("service_custom", []) or []

    broad_services = []

    # Service names that indicate broad/permissive definitions
    broad_patterns = {"ALL", "ALL_TCP", "ALL_UDP", "ANY"}

    for entry in services:
        if not isinstance(entry, dict):
            continue
        for svc_name, svc_data in entry.items():
            if not isinstance(svc_data, dict):
                continue

            is_broad = False

            # Check by name pattern
            if svc_name.upper() in broad_patterns:
                is_broad = True

            # Check if protocol is "IP" (all protocols)
            if svc_data.get("protocol") == "IP":
                is_broad = True

            # Check for port ranges that are suspiciously broad
            tcp_ports = svc_data.get("tcp-portrange", "")
            udp_ports = svc_data.get("udp-portrange", "")
            sctp_ports = svc_data.get("sctp-portrange", "")

            # If tcp-portrange is "1:65535" or similar, it's all ports
            for port_str in [tcp_ports, udp_ports, sctp_ports]:
                if port_str and ("1:65535" in str(port_str) or "0:65535" in str(port_str)):
                    is_broad = True

            if is_broad:
                broad_services.append(svc_name)

    if not broad_services:
        return []

    findings.append(
        (
            "### Broad service objects detected\n\n"
            "Service objects with permissive or all-encompassing definitions "
            "(e.g., 'ALL', protocol='IP', port range 1:65535) allow too many "
            "services and should be replaced with more specific definitions.\n"
        )
    )

    for svc_name in broad_services:
        findings.append(f"* **{svc_name}**")

    findings.append("")
    return findings
