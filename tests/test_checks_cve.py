"""Tests for CVE check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import CVECheckResult, CVEResult, Status
from hapr.framework.checks.cve import (
    check_critical_cves,
    check_high_cves,
    check_request_smuggling_cve,
)


# ---------------------------------------------------------------------------
# HAPR-CVE-001: Critical CVEs
# ---------------------------------------------------------------------------

class TestCriticalCVEs:
    """Test check_critical_cves for HAPR-CVE-001."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_cve_results(self):
        finding = check_critical_cves(self._make_config(), None)
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_na_no_version(self):
        finding = check_critical_cves(self._make_config(), CVECheckResult(version=""))
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_error_cve_lookup_failed(self):
        cve_result = CVECheckResult(version="2.4.0", error="API timeout")
        finding = check_critical_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.ERROR

    def test_pass_no_critical_cves(self):
        cve_result = CVECheckResult(
            version="2.8.0",
            cves=[CVEResult(cve_id="CVE-2023-1234", severity="high")],
        )
        finding = check_critical_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.PASS

    def test_fail_critical_cve_found(self):
        cve_result = CVECheckResult(
            version="2.4.0",
            cves=[CVEResult(cve_id="CVE-2021-40346", severity="critical")],
        )
        finding = check_critical_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.FAIL

    def test_pass_empty_cve_list(self):
        cve_result = CVECheckResult(version="2.8.3", cves=[])
        finding = check_critical_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-001"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-CVE-002: High Severity CVEs
# ---------------------------------------------------------------------------

class TestHighCVEs:
    """Test check_high_cves for HAPR-CVE-002."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_cve_results(self):
        finding = check_high_cves(self._make_config(), None)
        assert finding.check_id == "HAPR-CVE-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_na_no_version(self):
        finding = check_high_cves(self._make_config(), CVECheckResult(version=""))
        assert finding.check_id == "HAPR-CVE-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_error_cve_lookup_failed(self):
        cve_result = CVECheckResult(version="2.4.0", error="API timeout")
        finding = check_high_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-002"
        assert finding.status == Status.ERROR

    def test_pass_no_high_cves(self):
        cve_result = CVECheckResult(
            version="2.8.0",
            cves=[CVEResult(cve_id="CVE-2023-1234", severity="critical")],
        )
        finding = check_high_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-002"
        assert finding.status == Status.PASS

    def test_fail_high_cve_found(self):
        cve_result = CVECheckResult(
            version="2.4.0",
            cves=[CVEResult(cve_id="CVE-2023-5678", severity="high")],
        )
        finding = check_high_cves(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-002"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-CVE-003: Request Smuggling CVE-2021-40346
# ---------------------------------------------------------------------------

class TestRequestSmugglingCVE:
    """Test check_request_smuggling_cve for HAPR-CVE-003."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_cve_results(self):
        finding = check_request_smuggling_cve(self._make_config(), None)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_na_no_version(self):
        finding = check_request_smuggling_cve(
            self._make_config(), CVECheckResult(version="")
        )
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_fail_vulnerable_2_0_24(self):
        cve_result = CVECheckResult(version="2.0.24")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_pass_patched_2_0_25(self):
        cve_result = CVECheckResult(version="2.0.25")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.PASS

    def test_fail_vulnerable_2_2_16(self):
        cve_result = CVECheckResult(version="2.2.16")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_pass_patched_2_2_17(self):
        cve_result = CVECheckResult(version="2.2.17")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.PASS

    def test_fail_vulnerable_2_3_13(self):
        cve_result = CVECheckResult(version="2.3.13")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_pass_patched_2_3_14(self):
        cve_result = CVECheckResult(version="2.3.14")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.PASS

    def test_fail_vulnerable_2_4_3(self):
        cve_result = CVECheckResult(version="2.4.3")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_pass_patched_2_4_4(self):
        cve_result = CVECheckResult(version="2.4.4")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.PASS

    def test_fail_vulnerable_1_x(self):
        cve_result = CVECheckResult(version="1.9.16")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_fail_vulnerable_2_1_x(self):
        """2.1.x is EOL and all versions are vulnerable."""
        cve_result = CVECheckResult(version="2.1.7")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.FAIL

    def test_pass_modern_version(self):
        cve_result = CVECheckResult(version="2.8.3")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.PASS

    def test_error_unparseable_version(self):
        cve_result = CVECheckResult(version="not-a-version")
        finding = check_request_smuggling_cve(self._make_config(), cve_result)
        assert finding.check_id == "HAPR-CVE-003"
        assert finding.status == Status.ERROR
