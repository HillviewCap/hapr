"""HAProxy version CVE lookup via NVD API."""

from __future__ import annotations

import logging

from .models import CVECheckResult, CVEResult

log = logging.getLogger(__name__)


def check_cves(version: str, api_key: str | None = None) -> CVECheckResult:
    """Query the NVD API for known CVEs affecting a HAProxy version.

    Parameters
    ----------
    version:
        HAProxy version string (e.g., "2.6.0").
    api_key:
        Optional NVD API key for higher rate limits.

    Returns
    -------
    CVECheckResult
        Summary of CVEs found for the version.
    """
    result = CVECheckResult(version=version)

    try:
        import nvdlib
    except ImportError:
        result.error = "nvdlib is not installed — run: pip install nvdlib"
        log.error(result.error)
        return result

    # Build CPE match string for HAProxy
    cpe_name = f"cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*"

    try:
        kwargs: dict = {"cpeName": cpe_name}
        if api_key:
            kwargs["key"] = api_key

        cves = nvdlib.searchCVE(**kwargs)

        for cve in cves:
            cve_id = cve.id
            description = ""
            if cve.descriptions:
                for desc in cve.descriptions:
                    if desc.lang == "en":
                        description = desc.value
                        break
                if not description:
                    description = cve.descriptions[0].value

            # Extract CVSS score and severity
            cvss_score = 0.0
            severity = "unknown"

            if hasattr(cve, "metrics") and cve.metrics:
                # Try CVSS v3.1 first, then v3.0, then v2
                if hasattr(cve.metrics, "cvssMetricV31") and cve.metrics.cvssMetricV31:
                    m = cve.metrics.cvssMetricV31[0]
                    cvss_score = m.cvssData.baseScore
                    severity = m.cvssData.baseSeverity.lower()
                elif hasattr(cve.metrics, "cvssMetricV30") and cve.metrics.cvssMetricV30:
                    m = cve.metrics.cvssMetricV30[0]
                    cvss_score = m.cvssData.baseScore
                    severity = m.cvssData.baseSeverity.lower()
                elif hasattr(cve.metrics, "cvssMetricV2") and cve.metrics.cvssMetricV2:
                    m = cve.metrics.cvssMetricV2[0]
                    cvss_score = m.cvssData.baseScore
                    severity = _v2_severity(cvss_score)

            published = str(cve.published) if hasattr(cve, "published") else ""

            result.cves.append(CVEResult(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ))

        # Count by severity
        for c in result.cves:
            sev = c.severity.lower()
            if sev == "critical":
                result.critical_count += 1
            elif sev == "high":
                result.high_count += 1
            elif sev == "medium":
                result.medium_count += 1
            elif sev == "low":
                result.low_count += 1

        log.info(
            "Found %d CVE(s) for HAProxy %s (C:%d H:%d M:%d L:%d)",
            len(result.cves), version,
            result.critical_count, result.high_count,
            result.medium_count, result.low_count,
        )

    except Exception as exc:
        result.error = f"NVD API query failed: {exc}"
        log.warning(result.error)

    return result


def _v2_severity(score: float) -> str:
    """Map CVSS v2 score to severity string."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    else:
        return "low"
