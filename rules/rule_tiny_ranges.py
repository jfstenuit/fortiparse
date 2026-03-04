SECTION = "1_objects"
TITLE = "Tiny IP range objects"

import socket
import struct


def _ip_to_int(ip_str):
    """Convert IPv4 address string to integer."""
    try:
        return struct.unpack(">L", socket.inet_aton(ip_str))[0]
    except (socket.error, struct.error):
        return None


def run(vdom):
    """Detect IP range objects that cover only a few addresses.

    Ranges with very few IPs (< 5) are often better represented as individual
    address objects or subnet objects. This rule identifies tiny ranges that
    may indicate imprecise configuration or opportunities to simplify.
    """
    findings = []

    addrs = vdom.get("firewall", {}).get("address", []) or []

    tiny_ranges = []

    for entry in addrs:
        if not isinstance(entry, dict):
            continue
        for obj_name, obj_data in entry.items():
            if not isinstance(obj_data, dict):
                continue

            # Check for iprange type with start/end IPs
            start_ip = obj_data.get("start-ip")
            end_ip = obj_data.get("end-ip")

            if not start_ip or not end_ip:
                continue

            start_int = _ip_to_int(start_ip)
            end_int = _ip_to_int(end_ip)

            if start_int is None or end_int is None:
                continue

            # Calculate number of IPs in range
            ip_count = end_int - start_int + 1

            # Flag if tiny (< 5 IPs)
            if ip_count < 5:
                tiny_ranges.append((obj_name, start_ip, end_ip, ip_count))

    if not tiny_ranges:
        return []

    findings.append(
        (
            "### Tiny IP ranges detected\n\n"
            "Address range objects containing only a few IPs are often better "
            "represented as individual subnet objects or grouped in address groups. "
            "Consider consolidating or rephrasing these ranges.\n"
        )
    )

    for name, start, end, count in tiny_ranges:
        findings.append(f"* **{name}** ({start} - {end}): {count} IP(s)")

    findings.append("")
    return findings
