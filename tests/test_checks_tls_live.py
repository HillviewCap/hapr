"""Tests for TLS live scan check functions."""
from __future__ import annotations

from datetime import datetime, timedelta

from hapr.parser import parse_string
from hapr.models import CertInfo, ScanResult, Status
from hapr.framework.checks.tls_live import (
    check_deprecated_protocols_live,
    check_weak_ciphers_live,
    check_certificate_chain,
    check_certificate_expiry,
    check_tls_vulnerabilities,
    check_secure_renegotiation_live,
    check_certificate_key_size,
    check_certificate_expiry_warning,
    check_certificate_hostname_match,
)


# ---------------------------------------------------------------------------
# 5. HAPR-SCAN-007: Certificate Key Size (live scan)
# ---------------------------------------------------------------------------

class TestCertificateKeySize:
    """Test check_certificate_key_size for HAPR-SCAN-007."""

    def test_pass_adequate_key_size(self):
        config = parse_string("global\n  log stdout format raw local0")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            cert_info=CertInfo(
                key_size=4096,
                signature_algorithm="sha256WithRSAEncryption",
            ),
        )]
        finding = check_certificate_key_size(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.PASS

    def test_fail_small_key_size(self):
        config = parse_string("global\n  log stdout format raw local0")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            cert_info=CertInfo(
                key_size=1024,
                signature_algorithm="sha256WithRSAEncryption",
            ),
        )]
        finding = check_certificate_key_size(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.FAIL

    def test_na_empty_scan_results(self):
        config = parse_string("global\n  log stdout format raw local0")
        finding = check_certificate_key_size(config, [])
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 6. HAPR-SCAN-008: Certificate Expiry Warning (live scan)
# ---------------------------------------------------------------------------

class TestCertificateExpiryWarning:
    """Test check_certificate_expiry_warning for HAPR-SCAN-008."""

    def test_pass_far_future_expiry(self):
        config = parse_string("global\n  log stdout format raw local0")
        future_date = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            cert_info=CertInfo(
                not_after=future_date,
            ),
        )]
        finding = check_certificate_expiry_warning(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.PASS

    def test_partial_expiring_soon(self):
        config = parse_string("global\n  log stdout format raw local0")
        soon_date = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d %H:%M:%S")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            cert_info=CertInfo(
                not_after=soon_date,
            ),
        )]
        finding = check_certificate_expiry_warning(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.PARTIAL

    def test_na_empty_scan_results(self):
        config = parse_string("global\n  log stdout format raw local0")
        finding = check_certificate_expiry_warning(config, [])
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 7. HAPR-SCAN-009: Certificate Hostname Match (live scan)
# ---------------------------------------------------------------------------

class TestCertificateHostnameMatch:
    """Test check_certificate_hostname_match for HAPR-SCAN-009."""

    def test_pass_matching_hostname(self):
        config = parse_string("global\n  log stdout format raw local0")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            cert_info=CertInfo(
                subject="CN=example.com",
                san_entries=["example.com"],
            ),
        )]
        finding = check_certificate_hostname_match(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.PASS

    def test_fail_mismatched_hostname(self):
        config = parse_string("global\n  log stdout format raw local0")
        scan_results = [ScanResult(
            target="other.com",
            port=443,
            cert_info=CertInfo(
                subject="CN=example.com",
                san_entries=["example.com"],
            ),
        )]
        finding = check_certificate_hostname_match(config, scan_results)
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.FAIL

    def test_na_empty_scan_results(self):
        config = parse_string("global\n  log stdout format raw local0")
        finding = check_certificate_hostname_match(config, [])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-SCAN-001: Deprecated Protocols Live
# ---------------------------------------------------------------------------

class TestDeprecatedProtocolsLive:
    """Test check_deprecated_protocols_live for HAPR-SCAN-001."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_deprecated_protocols_live(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_no_deprecated_protocols(self):
        sr = ScanResult(
            target="example.com", port=443,
            accepted_protocols=["TLSv1.2", "TLSv1.3"],
        )
        finding = check_deprecated_protocols_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-001"
        assert finding.status == Status.PASS

    def test_fail_deprecated_protocol_accepted(self):
        sr = ScanResult(
            target="example.com", port=443,
            accepted_protocols=["TLSv1.0", "TLSv1.2"],
        )
        finding = check_deprecated_protocols_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-001"
        assert finding.status == Status.FAIL

    def test_skips_errored_results(self):
        sr = ScanResult(
            target="example.com", port=443,
            accepted_protocols=["TLSv1.0"],
            error="connection refused",
        )
        finding = check_deprecated_protocols_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-001"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-SCAN-002: Weak Ciphers Live
# ---------------------------------------------------------------------------

class TestWeakCiphersLive:
    """Test check_weak_ciphers_live for HAPR-SCAN-002."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_weak_ciphers_live(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_strong_ciphers_only(self):
        sr = ScanResult(
            target="example.com", port=443,
            accepted_ciphers={"TLSv1.2": ["ECDHE-RSA-AES128-GCM-SHA256"]},
        )
        finding = check_weak_ciphers_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-002"
        assert finding.status == Status.PASS

    def test_fail_weak_cipher_found(self):
        sr = ScanResult(
            target="example.com", port=443,
            accepted_ciphers={"TLSv1.2": ["RC4-SHA", "ECDHE-RSA-AES128-GCM-SHA256"]},
        )
        finding = check_weak_ciphers_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-002"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-SCAN-003: Certificate Chain
# ---------------------------------------------------------------------------

class TestCertificateChain:
    """Test check_certificate_chain for HAPR-SCAN-003."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_certificate_chain(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_na_no_cert_info(self):
        sr = ScanResult(target="example.com", port=443, cert_info=None)
        finding = check_certificate_chain(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_valid_chain(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(chain_valid=True, is_self_signed=False),
        )
        finding = check_certificate_chain(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-003"
        assert finding.status == Status.PASS

    def test_fail_invalid_chain(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(chain_valid=False),
        )
        finding = check_certificate_chain(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-003"
        assert finding.status == Status.FAIL

    def test_fail_self_signed(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(chain_valid=True, is_self_signed=True),
        )
        finding = check_certificate_chain(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-003"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-SCAN-004: Certificate Expiry
# ---------------------------------------------------------------------------

class TestCertificateExpiry:
    """Test check_certificate_expiry for HAPR-SCAN-004."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_certificate_expiry(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-004"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_not_expired(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(is_expired=False),
        )
        finding = check_certificate_expiry(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-004"
        assert finding.status == Status.PASS

    def test_fail_expired(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(is_expired=True, not_after="2023-01-01"),
        )
        finding = check_certificate_expiry(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-004"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-SCAN-005: TLS Vulnerabilities
# ---------------------------------------------------------------------------

class TestTLSVulnerabilities:
    """Test check_tls_vulnerabilities for HAPR-SCAN-005."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_tls_vulnerabilities(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-005"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_no_vulnerabilities(self):
        sr = ScanResult(
            target="example.com", port=443,
            vulnerabilities={"Heartbleed": False, "ROBOT": False, "CCS Injection": False},
        )
        finding = check_tls_vulnerabilities(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-005"
        assert finding.status == Status.PASS

    def test_fail_heartbleed(self):
        sr = ScanResult(
            target="example.com", port=443,
            vulnerabilities={"Heartbleed": True, "ROBOT": False},
        )
        finding = check_tls_vulnerabilities(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-005"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-SCAN-006: Secure Renegotiation Live
# ---------------------------------------------------------------------------

class TestSecureRenegotiationLive:
    """Test check_secure_renegotiation_live for HAPR-SCAN-006."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_secure_renegotiation_live(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-006"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_secure_renegotiation(self):
        sr = ScanResult(
            target="example.com", port=443,
            secure_renegotiation=True,
        )
        finding = check_secure_renegotiation_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-006"
        assert finding.status == Status.PASS

    def test_fail_insecure_renegotiation(self):
        sr = ScanResult(
            target="example.com", port=443,
            secure_renegotiation=False,
        )
        finding = check_secure_renegotiation_live(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-006"
        assert finding.status == Status.FAIL

    def test_skips_errored_and_counts_correctly(self):
        """Bug fix: errored results are skipped and the checked count is correct."""
        sr_ok = ScanResult(
            target="good.example.com", port=443,
            secure_renegotiation=True,
        )
        sr_err = ScanResult(
            target="bad.example.com", port=443,
            error="connection refused",
            secure_renegotiation=False,
        )
        finding = check_secure_renegotiation_live(
            self._make_config(), [sr_ok, sr_err]
        )
        assert finding.check_id == "HAPR-SCAN-006"
        assert finding.status == Status.PASS
        # Evidence should say "Checked 1 target(s)" not "Checked 2 target(s)"
        assert "1 target" in finding.evidence


# ---------------------------------------------------------------------------
# HAPR-SCAN-007: Certificate Key Size
# ---------------------------------------------------------------------------

class TestCertificateKeySizeExtended:
    """Test check_certificate_key_size for HAPR-SCAN-007."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_certificate_key_size(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_rsa_2048(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(key_size=2048, signature_algorithm="sha256WithRSAEncryption"),
        )
        finding = check_certificate_key_size(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.PASS

    def test_pass_ecdsa_256(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(key_size=256, signature_algorithm="ecdsa-with-SHA256"),
        )
        finding = check_certificate_key_size(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.PASS

    def test_fail_rsa_1024(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(key_size=1024, signature_algorithm="sha256WithRSAEncryption"),
        )
        finding = check_certificate_key_size(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-007"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-SCAN-008: Certificate Expiry Warning
# ---------------------------------------------------------------------------

class TestCertificateExpiryWarningExtended:
    """Test check_certificate_expiry_warning for HAPR-SCAN-008."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_certificate_expiry_warning(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_cert_expires_far_away(self):
        from datetime import datetime, timedelta
        future = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(not_after=future),
        )
        finding = check_certificate_expiry_warning(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.PASS

    def test_partial_cert_expires_within_30_days(self):
        from datetime import datetime, timedelta
        soon = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d %H:%M:%S")
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(not_after=soon),
        )
        finding = check_certificate_expiry_warning(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-008"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# HAPR-SCAN-009: Certificate Hostname Match
# ---------------------------------------------------------------------------

class TestCertificateHostnameMatchExtended:
    """Test check_certificate_hostname_match for HAPR-SCAN-009."""

    def _make_config(self):
        return parse_string("global\n    log /dev/log local0\n")

    def test_na_no_scan_results(self):
        finding = check_certificate_hostname_match(self._make_config(), [])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_san_match(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(
                subject="CN=example.com",
                san_entries=["example.com", "www.example.com"],
            ),
        )
        finding = check_certificate_hostname_match(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.PASS

    def test_pass_wildcard_san_match(self):
        sr = ScanResult(
            target="sub.example.com", port=443,
            cert_info=CertInfo(
                subject="CN=example.com",
                san_entries=["*.example.com"],
            ),
        )
        finding = check_certificate_hostname_match(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.PASS

    def test_pass_subject_cn_fallback(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(subject="CN=example.com", san_entries=[]),
        )
        finding = check_certificate_hostname_match(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.PASS

    def test_fail_hostname_mismatch(self):
        sr = ScanResult(
            target="example.com", port=443,
            cert_info=CertInfo(
                subject="CN=other.com",
                san_entries=["other.com"],
            ),
        )
        finding = check_certificate_hostname_match(self._make_config(), [sr])
        assert finding.check_id == "HAPR-SCAN-009"
        assert finding.status == Status.FAIL
