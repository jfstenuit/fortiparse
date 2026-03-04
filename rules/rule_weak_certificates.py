SECTION = "5_management"
TITLE = "Weak or insecure management certificates"

import datetime


def _is_self_signed(cert):
    """Self-signed if subject == issuer."""
    subj = cert.get("subject")
    issuer = cert.get("issuer")
    return subj and issuer and subj == issuer


def _is_expired(cert):
    """Check certificate expiration based on JSON field 'valid-to'."""
    valid_to = cert.get("valid-to")
    if not valid_to:
        return False
    try:
        # Expected format: "2025-01-23 12:40:00"
        expiry = datetime.datetime.strptime(valid_to, "%Y-%m-%d %H:%M:%S")
        return expiry < datetime.datetime.now()
    except Exception:
        return False


def _is_weak_key(cert):
    """Detect weak key sizes: RSA/DSA <2048, EC <256."""
    algo = cert.get("key-type", "").lower()
    size = cert.get("key-size")
    if not algo or not isinstance(size, int):
        return False

    if algo in ("rsa", "dsa") and size < 2048:
        return True
    if algo in ("ecdsa", "ec") and size < 256:
        return True

    return False


def _is_sha1_signed(cert):
    """Detect SHA1-signed certificates."""
    sig = cert.get("signature-algorithm", "").lower()
    return "sha1" in sig and "sha256" not in sig and "sha384" not in sig and "sha512" not in sig


def _is_factory_fortinet(cert):
    """Detect Fortinet factory certificates."""
    name = cert.get("name", "").lower()
    issuer = cert.get("issuer", "").lower()

    patterns = [
        "fortinet_ca_ssl",
        "fortinet",     # Fortinet self-signed admin certs
        "fgfm",         # FortiGate management CA
        "factory"
    ]

    return any(p in name for p in patterns) or any(p in issuer for p in patterns)


def run(vdom):
    """
    Detect weak or insecure certificates used for management.
    This module supports flexible JSON structures and does not rely on assumptions.
    """

    findings = []

    # =========================================
    # Certificate pools
    # =========================================
    certs = []

    # Certificates may appear under several locations depending on export:
    paths_to_check = [
        ("certificate_local", []),
        ("certificate_ca", []),
        ("pki", "certificate"),
        ("vpn_ssl_settings", "server-cert"),      # SSL-VPN admin cert reference
        ("system_global", "admin-server-cert"),   # Admin GUI certificate reference
    ]

    # 1. Direct certificate arrays
    if "certificate_local" in vdom:
        certs.extend(vdom["certificate_local"])

    if "certificate_ca" in vdom:
        certs.extend(vdom["certificate_ca"])

    # 2. PKI / other structures
    pki = vdom.get("pki", {})
    if isinstance(pki, dict) and "certificate" in pki:
        certs.extend(pki["certificate"])

    # =========================================
    # If references to cert names exist, we warn (but cannot resolve)
    # =========================================
    sslvpn = vdom.get("vpn_ssl_settings", {})
    admin_cert_name = vdom.get("system_global", {}).get("admin-server-cert")

    if admin_cert_name:
        findings.append(
            f"* Admin GUI uses certificate `{admin_cert_name}` (reference only, cannot resolve details)"
        )

    if "server-cert" in sslvpn:
        findings.append(
            f"* SSL-VPN uses certificate `{sslvpn.get('server-cert')}` (reference only, cannot resolve details)"
        )

    # =========================================
    # Evaluate actual certificate objects
    # =========================================
    for cert in certs:
        if not isinstance(cert, dict):
            continue

        name = cert.get("name", "<unnamed>")

        # 1. Self-signed
        if _is_self_signed(cert):
            findings.append(f"* **{name}**: self-signed certificate")

        # 2. Expired
        if _is_expired(cert):
            findings.append(f"* **{name}**: expired certificate (`valid-to: {cert.get('valid-to')}`)")

        # 3. Weak key
        if _is_weak_key(cert):
            findings.append(
                f"* **{name}**: weak key size `{cert.get('key-size')}` for `{cert.get('key-type')}`"
            )

        # 4. SHA1 signature
        if _is_sha1_signed(cert):
            findings.append(
                f"* **{name}**: weak signature algorithm `{cert.get('signature-algorithm')}`"
            )

        # 5. Factory Fortinet cert
        if _is_factory_fortinet(cert):
            findings.append(f"* **{name}**: factory or default Fortinet certificate")

    # =========================================
    # Output formatting
    # =========================================
    if not findings:
        return []

    header = (
        "### Weak or insecure certificates\n\n"
        "The certificates used by management or SSL/VPN components exhibit one or more "
        "security weaknesses. These issues may enable man-in-the-middle attacks, "
        "downgrade attacks, or the use of deprecated cryptography.\n"
    )

    md = [header]
    md.extend(findings)
    md.append("")
    return md