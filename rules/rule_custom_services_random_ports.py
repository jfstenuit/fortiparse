SECTION = "1_objects"
TITLE = "Custom services with random/non-standard ports"


def _is_standard_port(port_num):
    """Check if a port is in the standard/well-known range."""
    # Well-known and common service ports
    standard_ports = {
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        80,  # HTTP
        110,  # POP3
        143,  # IMAP
        389,  # LDAP
        443,  # HTTPS
        445,  # SMB
        465,  # SMTPS
        587,  # SMTP-Submission
        636,  # LDAPS
        989,  # FTPS
        990,  # FTPS
        993,  # IMAPS
        995,  # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080,  # HTTP-Alt
        8443,  # HTTPS-Alt
    }
    return port_num in standard_ports


def _parse_port(port_str):
    """Parse port string (e.g., "8765" or "1234:5678") and return list of ports."""
    if not port_str:
        return []
    port_str = str(port_str).strip()
    if ":" in port_str:
        # Range format
        try:
            start, end = map(int, port_str.split(":"))
            return [start, end]  # Return start and end for inspection
        except (ValueError, IndexError):
            return []
    else:
        # Single port
        try:
            return [int(port_str)]
        except ValueError:
            return []


def run(vdom):
    """Detect custom service objects using non-standard or arbitrary ports.

    Services with randomly assigned or non-standard high ports (e.g., 9876,
    12345, etc.) often indicate ad-hoc configuration and should be reviewed
    to ensure they align with documented standards.
    """
    findings = []

    services = vdom.get("firewall", {}).get("service_custom", []) or []

    random_port_services = []

    for entry in services:
        if not isinstance(entry, dict):
            continue
        for svc_name, svc_data in entry.items():
            if not isinstance(svc_data, dict):
                continue

            has_random_port = False
            port_info = []

            # Check TCP ports
            tcp_ports = svc_data.get("tcp-portrange")
            if tcp_ports:
                parsed = _parse_port(tcp_ports)
                for port in parsed:
                    if port > 1024 and not _is_standard_port(port):
                        has_random_port = True
                        port_info.append(f"TCP {tcp_ports}")

            # Check UDP ports
            udp_ports = svc_data.get("udp-portrange")
            if udp_ports:
                parsed = _parse_port(udp_ports)
                for port in parsed:
                    if port > 1024 and not _is_standard_port(port):
                        has_random_port = True
                        port_info.append(f"UDP {udp_ports}")

            # Check SCTP ports
            sctp_ports = svc_data.get("sctp-portrange")
            if sctp_ports:
                parsed = _parse_port(sctp_ports)
                for port in parsed:
                    if port > 1024 and not _is_standard_port(port):
                        has_random_port = True
                        port_info.append(f"SCTP {sctp_ports}")

            if has_random_port:
                random_port_services.append((svc_name, port_info))

    if not random_port_services:
        return []

    findings.append(
        (
            "### Custom services with non-standard/random ports\n\n"
            "Services using arbitrary or non-standard high ports (>1024) may "
            "indicate ad-hoc configuration. Ensure these are documented and "
            "intentional rather than misconfigured or bypass rules.\n"
        )
    )

    for svc_name, ports in random_port_services:
        port_detail = "; ".join(ports)
        findings.append(f"* **{svc_name}**: {port_detail}")

    findings.append("")
    return findings
