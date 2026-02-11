"""Live TLS scan check functions.

These checks consume sslyze scan results to verify actual TLS behavior
matches the intended configuration.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ...models import Finding, HAProxyConfig, ScanResult, Status

# Protocols considered deprecated / insecure
_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
                          "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

# Cipher strings / keywords that indicate weakness
_WEAK_CIPHER_KEYWORDS = (
    "RC4", "DES", "3DES", "NULL", "EXPORT", "aNULL", "eNULL",
    "MD5", "DES-CBC", "RC2", "SEED", "IDEA", "CAMELLIA",
)


def check_deprecated_protocols_live(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-001: Verify no deprecated TLS versions are accepted in live scan.

    Config may enforce TLS 1.2+, but a live scan confirms the server
    actually rejects TLS 1.0 and 1.1 connections.
    """
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-001",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    deprecated_accepted = []
    for sr in scan_results:
        if sr.error:
            continue
        for proto in sr.accepted_protocols:
            normalized = proto.strip()
            if normalized in _DEPRECATED_PROTOCOLS:
                deprecated_accepted.append(f"{sr.target}:{sr.port} accepts {normalized}")

    if not deprecated_accepted:
        return Finding(
            check_id="HAPR-SCAN-001",
            status=Status.PASS,
            message="No deprecated TLS/SSL protocols accepted by any target",
            evidence="All targets reject SSLv2, SSLv3, TLS 1.0, TLS 1.1",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-001",
            status=Status.FAIL,
            message=f"Deprecated protocols accepted on {len(deprecated_accepted)} target(s)",
            evidence="; ".join(deprecated_accepted[:5]),
        )


def check_weak_ciphers_live(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-002: Verify no weak cipher suites are negotiated in live scan."""
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-002",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    weak_found = []
    for sr in scan_results:
        if sr.error:
            continue
        for proto, ciphers in sr.accepted_ciphers.items():
            for cipher in ciphers:
                if any(wk in cipher.upper() for wk in _WEAK_CIPHER_KEYWORDS):
                    weak_found.append(f"{sr.target}:{sr.port} [{proto}] {cipher}")

    if not weak_found:
        return Finding(
            check_id="HAPR-SCAN-002",
            status=Status.PASS,
            message="No weak cipher suites accepted by any target",
            evidence="All negotiated ciphers are strong",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-002",
            status=Status.FAIL,
            message=f"Weak ciphers accepted: {len(weak_found)} weak cipher(s) found",
            evidence="; ".join(weak_found[:5]),
        )


def check_certificate_chain(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-003: Verify certificate chain is valid and trusted."""
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-003",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    issues = []
    checked = 0
    for sr in scan_results:
        if sr.error or sr.cert_info is None:
            continue
        checked += 1
        if not sr.cert_info.chain_valid:
            issues.append(f"{sr.target}:{sr.port} has invalid certificate chain")
        if sr.cert_info.is_self_signed:
            issues.append(f"{sr.target}:{sr.port} uses self-signed certificate")

    if checked == 0:
        return Finding(
            check_id="HAPR-SCAN-003",
            status=Status.NOT_APPLICABLE,
            message="No certificate information available from scan",
        )

    if not issues:
        return Finding(
            check_id="HAPR-SCAN-003",
            status=Status.PASS,
            message="All certificate chains are valid and trusted",
            evidence=f"Checked {checked} target(s)",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-003",
            status=Status.FAIL,
            message=f"Certificate chain issues found on {len(issues)} target(s)",
            evidence="; ".join(issues[:5]),
        )


def check_certificate_expiry(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-004: Verify certificates are not expired."""
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-004",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    expired = []
    checked = 0
    for sr in scan_results:
        if sr.error or sr.cert_info is None:
            continue
        checked += 1
        if sr.cert_info.is_expired:
            expired.append(
                f"{sr.target}:{sr.port} certificate expired "
                f"(not_after: {sr.cert_info.not_after})"
            )

    if checked == 0:
        return Finding(
            check_id="HAPR-SCAN-004",
            status=Status.NOT_APPLICABLE,
            message="No certificate information available from scan",
        )

    if not expired:
        return Finding(
            check_id="HAPR-SCAN-004",
            status=Status.PASS,
            message="All certificates are within validity period",
            evidence=f"Checked {checked} target(s)",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-004",
            status=Status.FAIL,
            message=f"Expired certificates found on {len(expired)} target(s)",
            evidence="; ".join(expired),
        )


def check_tls_vulnerabilities(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-005: Check for known TLS vulnerabilities (Heartbleed, ROBOT, CCS injection)."""
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-005",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    vulns_found = []
    for sr in scan_results:
        if sr.error:
            continue
        for vuln_name, is_vulnerable in sr.vulnerabilities.items():
            if is_vulnerable:
                vulns_found.append(f"{sr.target}:{sr.port} vulnerable to {vuln_name}")

    if not vulns_found:
        return Finding(
            check_id="HAPR-SCAN-005",
            status=Status.PASS,
            message="No known TLS vulnerabilities detected",
            evidence="Checked: Heartbleed, ROBOT, CCS Injection, CRIME, insecure renegotiation",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-005",
            status=Status.FAIL,
            message=f"TLS vulnerabilities detected on {len(vulns_found)} target(s)",
            evidence="; ".join(vulns_found),
        )


def check_secure_renegotiation_live(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """HAPR-SCAN-006: Verify secure renegotiation is supported."""
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-006",
            status=Status.NOT_APPLICABLE,
            message="No scan results available",
        )

    insecure = []
    for sr in scan_results:
        if sr.error:
            continue
        if not sr.secure_renegotiation:
            insecure.append(f"{sr.target}:{sr.port} supports insecure renegotiation")

    if not insecure:
        return Finding(
            check_id="HAPR-SCAN-006",
            status=Status.PASS,
            message="All targets support secure renegotiation",
            evidence=f"Checked {len(scan_results)} target(s)",
        )
    else:
        return Finding(
            check_id="HAPR-SCAN-006",
            status=Status.FAIL,
            message="Insecure renegotiation detected",
            evidence="; ".join(insecure),
        )


# ---------------------------------------------------------------------------
# HAPR-SCAN-007  Certificate key size
# ---------------------------------------------------------------------------

def check_certificate_key_size(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """Check that certificate key sizes meet minimum requirements.

    RSA keys must be >= 2048 bits, ECDSA keys must be >= 256 bits.
    The key type is inferred from the certificate's signature algorithm.

    Returns PASS if all key sizes are adequate, FAIL if any are too small,
    N/A if no scan results or no certificate information is available.
    """
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-007",
            status=Status.NOT_APPLICABLE,
            message="No scan results available.",
        )

    inadequate: list[str] = []
    checked = 0
    for sr in scan_results:
        if sr.error or sr.cert_info is None:
            continue
        checked += 1
        key_size = sr.cert_info.key_size
        algo = sr.cert_info.signature_algorithm.lower()

        # Determine if this is an ECDSA/EC key or RSA
        if "ecdsa" in algo or "ec" in algo:
            min_size = 256
            key_type = "ECDSA"
        else:
            min_size = 2048
            key_type = "RSA"

        if key_size < min_size:
            inadequate.append(
                f"{sr.target}:{sr.port} {key_type} key is {key_size} bits "
                f"(minimum: {min_size})"
            )

    if checked == 0:
        return Finding(
            check_id="HAPR-SCAN-007",
            status=Status.NOT_APPLICABLE,
            message="No certificate information available from scan.",
        )

    if not inadequate:
        return Finding(
            check_id="HAPR-SCAN-007",
            status=Status.PASS,
            message="All certificate key sizes meet minimum requirements.",
            evidence=f"Checked {checked} target(s)",
        )

    return Finding(
        check_id="HAPR-SCAN-007",
        status=Status.FAIL,
        message=f"Inadequate key size found on {len(inadequate)} target(s).",
        evidence="; ".join(inadequate),
    )


# ---------------------------------------------------------------------------
# HAPR-SCAN-008  Certificate expiry warning (30 days)
# ---------------------------------------------------------------------------

# Date formats that sslyze may produce
_CERT_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%b %d %H:%M:%S %Y %Z",
    "%b %d %H:%M:%S %Y",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
)


def _parse_cert_date(date_str: str) -> datetime | None:
    """Try multiple date formats to parse a certificate date string."""
    for fmt in _CERT_DATE_FORMATS:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def check_certificate_expiry_warning(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """Warn if any certificate expires within 30 days.

    Parses the ``not_after`` field from certificate information and compares
    it to the current date.

    Returns PASS if all certs expire more than 30 days from now, PARTIAL if
    any expire within 30 days (but are not yet expired), N/A if no scan
    results or no certificate information is available.
    """
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-008",
            status=Status.NOT_APPLICABLE,
            message="No scan results available.",
        )

    now = datetime.now()
    warning_threshold = timedelta(days=30)
    expiring_soon: list[str] = []
    checked = 0

    for sr in scan_results:
        if sr.error or sr.cert_info is None:
            continue
        if not sr.cert_info.not_after:
            continue
        checked += 1

        expiry = _parse_cert_date(sr.cert_info.not_after)
        if expiry is None:
            continue

        # Strip timezone info for comparison if present
        if expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)

        remaining = expiry - now
        if remaining <= warning_threshold and remaining.total_seconds() > 0:
            expiring_soon.append(
                f"{sr.target}:{sr.port} expires in {remaining.days} day(s) "
                f"(not_after: {sr.cert_info.not_after})"
            )

    if checked == 0:
        return Finding(
            check_id="HAPR-SCAN-008",
            status=Status.NOT_APPLICABLE,
            message="No certificate information available from scan.",
        )

    if expiring_soon:
        return Finding(
            check_id="HAPR-SCAN-008",
            status=Status.PARTIAL,
            message=(
                f"{len(expiring_soon)} certificate(s) expire within 30 days."
            ),
            evidence="; ".join(expiring_soon),
        )

    return Finding(
        check_id="HAPR-SCAN-008",
        status=Status.PASS,
        message="All certificates expire more than 30 days from now.",
        evidence=f"Checked {checked} target(s)",
    )


# ---------------------------------------------------------------------------
# HAPR-SCAN-009  Certificate hostname match
# ---------------------------------------------------------------------------

def _hostname_matches(hostname: str, pattern: str) -> bool:
    """Check if a hostname matches a certificate name pattern.

    Supports wildcard certificates where ``*.example.com`` matches
    ``sub.example.com`` but not ``example.com`` or ``a.b.example.com``.
    """
    hostname = hostname.lower().strip()
    pattern = pattern.lower().strip()

    if hostname == pattern:
        return True

    # Wildcard matching: *.example.com
    if pattern.startswith("*."):
        # The wildcard only covers one level of subdomain
        wildcard_base = pattern[2:]
        # hostname must end with the wildcard base and have exactly one more label
        if hostname.endswith("." + wildcard_base):
            prefix = hostname[: -(len(wildcard_base) + 1)]
            # prefix must be a single label (no dots)
            if "." not in prefix and prefix:
                return True

    return False


def check_certificate_hostname_match(
    config: HAProxyConfig, scan_results: list[ScanResult]
) -> Finding:
    """Check that certificate subject/SAN entries match the target hostname.

    Compares the scan target against the certificate's Common Name (CN) in
    the subject field and all Subject Alternative Name (SAN) entries.
    Supports wildcard certificate matching.

    Returns PASS if all targets match their certificates, FAIL if any
    mismatch, N/A if no scan results or no certificate information.
    """
    if not scan_results:
        return Finding(
            check_id="HAPR-SCAN-009",
            status=Status.NOT_APPLICABLE,
            message="No scan results available.",
        )

    mismatches: list[str] = []
    checked = 0

    for sr in scan_results:
        if sr.error or sr.cert_info is None:
            continue
        checked += 1
        target = sr.target.lower().strip()
        matched = False

        # Check SAN entries first (preferred per RFC 6125)
        for san in sr.cert_info.san_entries:
            if _hostname_matches(target, san):
                matched = True
                break

        # Fall back to subject CN
        if not matched and sr.cert_info.subject:
            subject = sr.cert_info.subject
            # Extract CN from subject string (e.g., "CN=example.com" or
            # "C=US, ST=CA, O=Org, CN=example.com")
            cn = ""
            for part in subject.split(","):
                part = part.strip()
                if part.upper().startswith("CN="):
                    cn = part[3:].strip()
                    break
            if not cn:
                # Subject may just be the CN itself
                cn = subject
            if _hostname_matches(target, cn):
                matched = True

        if not matched:
            san_list = ", ".join(sr.cert_info.san_entries[:5]) if sr.cert_info.san_entries else "none"
            mismatches.append(
                f"{sr.target}:{sr.port} does not match cert "
                f"(subject: {sr.cert_info.subject}, SANs: {san_list})"
            )

    if checked == 0:
        return Finding(
            check_id="HAPR-SCAN-009",
            status=Status.NOT_APPLICABLE,
            message="No certificate information available from scan.",
        )

    if not mismatches:
        return Finding(
            check_id="HAPR-SCAN-009",
            status=Status.PASS,
            message="All certificate hostnames match their targets.",
            evidence=f"Checked {checked} target(s)",
        )

    return Finding(
        check_id="HAPR-SCAN-009",
        status=Status.FAIL,
        message=f"Certificate hostname mismatch on {len(mismatches)} target(s).",
        evidence="; ".join(mismatches),
    )
