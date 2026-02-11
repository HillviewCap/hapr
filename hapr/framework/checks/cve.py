"""CVE / version vulnerability check functions."""

from __future__ import annotations

from ...models import CVECheckResult, Finding, HAProxyConfig, Status


def check_critical_cves(
    config: HAProxyConfig, cve_results: CVECheckResult | None
) -> Finding:
    """HAPR-CVE-001: Check for critical CVEs affecting the detected HAProxy version."""
    if cve_results is None or not cve_results.version:
        return Finding(
            check_id="HAPR-CVE-001",
            status=Status.NOT_APPLICABLE,
            message="HAProxy version not detected — cannot check CVEs",
        )

    if cve_results.error:
        return Finding(
            check_id="HAPR-CVE-001",
            status=Status.ERROR,
            message=f"CVE lookup failed: {cve_results.error}",
        )

    critical = [c for c in cve_results.cves if c.severity.lower() == "critical"]

    if not critical:
        return Finding(
            check_id="HAPR-CVE-001",
            status=Status.PASS,
            message=f"No critical CVEs found for HAProxy {cve_results.version}",
            evidence=f"Version: {cve_results.version}",
        )
    else:
        cve_ids = ", ".join(c.cve_id for c in critical[:5])
        return Finding(
            check_id="HAPR-CVE-001",
            status=Status.FAIL,
            message=f"{len(critical)} critical CVE(s) found for HAProxy {cve_results.version}",
            evidence=f"Critical CVEs: {cve_ids}",
        )


def check_high_cves(
    config: HAProxyConfig, cve_results: CVECheckResult | None
) -> Finding:
    """HAPR-CVE-002: Check for high-severity CVEs affecting the detected HAProxy version."""
    if cve_results is None or not cve_results.version:
        return Finding(
            check_id="HAPR-CVE-002",
            status=Status.NOT_APPLICABLE,
            message="HAProxy version not detected — cannot check CVEs",
        )

    if cve_results.error:
        return Finding(
            check_id="HAPR-CVE-002",
            status=Status.ERROR,
            message=f"CVE lookup failed: {cve_results.error}",
        )

    high = [c for c in cve_results.cves if c.severity.lower() == "high"]

    if not high:
        return Finding(
            check_id="HAPR-CVE-002",
            status=Status.PASS,
            message=f"No high-severity CVEs found for HAProxy {cve_results.version}",
            evidence=f"Version: {cve_results.version}",
        )
    else:
        cve_ids = ", ".join(c.cve_id for c in high[:5])
        return Finding(
            check_id="HAPR-CVE-002",
            status=Status.FAIL,
            message=f"{len(high)} high-severity CVE(s) found for HAProxy {cve_results.version}",
            evidence=f"High CVEs: {cve_ids}",
        )


def check_request_smuggling_cve(
    config: HAProxyConfig, cve_results: CVECheckResult | None
) -> Finding:
    """HAPR-CVE-003: Specific check for CVE-2021-40346 (HTTP request smuggling).

    This CVE affects HAProxy versions before 2.0.25, 2.2.17, 2.3.14, and 2.4.4.
    It allows HTTP request smuggling via integer overflow in content-length handling.
    """
    if cve_results is None or not cve_results.version:
        return Finding(
            check_id="HAPR-CVE-003",
            status=Status.NOT_APPLICABLE,
            message="HAProxy version not detected — cannot check CVE-2021-40346",
        )

    version = cve_results.version
    try:
        parts = version.split(".")
        major = int(parts[0])
        minor = int(parts[1])
        patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return Finding(
            check_id="HAPR-CVE-003",
            status=Status.ERROR,
            message=f"Cannot parse version string: {version}",
        )

    vulnerable = False
    if major < 2:
        vulnerable = True
    elif major == 2:
        if minor == 0 and patch < 25:
            vulnerable = True
        elif minor == 2 and patch < 17:
            vulnerable = True
        elif minor == 3 and patch < 14:
            vulnerable = True
        elif minor == 4 and patch < 4:
            vulnerable = True
        elif minor == 1:
            # 2.1.x is EOL and all versions are vulnerable
            vulnerable = True

    if vulnerable:
        return Finding(
            check_id="HAPR-CVE-003",
            status=Status.FAIL,
            message=f"HAProxy {version} is vulnerable to CVE-2021-40346 (HTTP request smuggling)",
            evidence=f"Version {version} is below the fix versions (2.0.25, 2.2.17, 2.3.14, 2.4.4)",
        )
    else:
        return Finding(
            check_id="HAPR-CVE-003",
            status=Status.PASS,
            message=f"HAProxy {version} is not vulnerable to CVE-2021-40346",
            evidence=f"Version {version} is at or above the patched version",
        )
