"""Live TLS scan check functions.

These checks consume sslyze scan results to verify actual TLS behavior
matches the intended configuration.
"""

from __future__ import annotations

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
