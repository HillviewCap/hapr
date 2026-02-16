"""Tests for TLS check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import tls
from hapr.framework.checks.tls import (
    _find_weak_ciphers,
    check_no_weak_ciphers,
    check_min_tls_version,
    check_dh_param_size,
    check_hsts_configured,
    check_ocsp_stapling,
    check_fips_ciphers,
    check_mtls_client_verification,
    check_client_crl_configured,
    check_ssl_default_bind_options,
    check_ssl_default_bind_ciphers,
    check_ssl_default_bind_ciphersuites,
)


# ---------------------------------------------------------------------------
# Fix 1: HAPR-TLS-002 — Weak cipher detection
# ---------------------------------------------------------------------------

class TestWeakCipherDetection:
    """Test the new _find_weak_ciphers function and check_no_weak_ciphers."""

    def test_find_weak_des_cbc3_sha(self):
        result = _find_weak_ciphers("ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA")
        assert "DES-CBC3-SHA" in result

    def test_find_weak_rc4_sha(self):
        result = _find_weak_ciphers("ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA")
        assert "RC4-SHA" in result

    def test_exclusion_prefix_skipped(self):
        """Ciphers prefixed with ! are exclusions and should not be flagged."""
        result = _find_weak_ciphers("ECDHE+AESGCM:!RC4:!DES:!3DES")
        assert result == []

    def test_clean_cipher_string(self):
        result = _find_weak_ciphers(
            "ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES256:DHE+AES256"
        )
        assert result == []

    def test_multiple_weak_ciphers(self):
        result = _find_weak_ciphers("DES-CBC3-SHA:RC4-SHA:NULL-MD5:EXPORT-DES")
        assert len(result) == 4

    def test_check_no_weak_ciphers_fail(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:RC4-SHA
""")
        finding = check_no_weak_ciphers(config)
        assert finding.status == Status.FAIL
        assert "DES-CBC3-SHA" in finding.evidence
        assert "RC4-SHA" in finding.evidence

    def test_check_no_weak_ciphers_pass_with_exclusions(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:DHE+AESGCM:!aNULL:!MD5:!DSS:!RC4:!DES:!3DES:!EXPORT
""")
        finding = check_no_weak_ciphers(config)
        assert finding.status == Status.PASS

    def test_check_no_weak_ciphers_pass_clean(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:DHE+AESGCM
""")
        finding = check_no_weak_ciphers(config)
        assert finding.status == Status.PASS


class TestHSTSMaxAgeValidation:
    """Tests for HSTS max-age value validation."""

    def test_hsts_strong_max_age_passes(self):
        config = parse_string(
            "defaults\n"
            "    mode http\n"
            "    http-response set-header Strict-Transport-Security max-age=31536000;\\ includeSubDomains\n"
        )
        finding = check_hsts_configured(config)
        assert finding.status == Status.PASS

    def test_hsts_weak_max_age_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Strict-Transport-Security max-age=86400
""")
        finding = check_hsts_configured(config)
        assert finding.status == Status.PARTIAL

    def test_hsts_zero_max_age_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Strict-Transport-Security max-age=0
""")
        finding = check_hsts_configured(config)
        assert finding.status == Status.PARTIAL

    def test_hsts_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_hsts_configured(config)
        assert finding.status == Status.FAIL

    def test_hsts_very_large_max_age_passes(self):
        config = parse_string(
            "defaults\n"
            "    mode http\n"
            "    http-response set-header Strict-Transport-Security max-age=63072000;\\ includeSubDomains;\\ preload\n"
        )
        finding = check_hsts_configured(config)
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-TLS-008: TLS session tickets disabled
# ---------------------------------------------------------------------------

class TestTLSSessionTickets:
    """Test check_tls_session_tickets_disabled for HAPR-TLS-008."""

    def test_no_tls_tickets_in_global_passes(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3 no-tls-tickets
""")
        finding = tls.check_tls_session_tickets_disabled(config)
        assert finding.check_id == "HAPR-TLS-008"
        assert finding.status == Status.PASS

    def test_no_tls_tickets_missing_fails(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3
""")
        finding = tls.check_tls_session_tickets_disabled(config)
        assert finding.check_id == "HAPR-TLS-008"
        assert finding.status == Status.FAIL

    def test_no_bind_options_at_all_fails(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = tls.check_tls_session_tickets_disabled(config)
        assert finding.check_id == "HAPR-TLS-008"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-009: SSL default server options
# ---------------------------------------------------------------------------

class TestSSLDefaultServerOptions:
    """Test check_ssl_default_server_options for HAPR-TLS-009."""

    def test_ssl_default_server_options_present_passes(self):
        config = parse_string("""
global
    ssl-default-server-options ssl-min-ver TLSv1.2
""")
        finding = tls.check_ssl_default_server_options(config)
        assert finding.check_id == "HAPR-TLS-009"
        assert finding.status == Status.PASS

    def test_ssl_default_server_options_missing_fails(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = tls.check_ssl_default_server_options(config)
        assert finding.check_id == "HAPR-TLS-009"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 1. HAPR-TLS-010: OCSP Stapling
# ---------------------------------------------------------------------------

class TestOCSPStapling:
    """Test check_ocsp_stapling for HAPR-TLS-010."""

    def test_pass_ocsp_update_on(self):
        config = parse_string("""
frontend ft_ssl
    bind *:443 ssl crt /cert.pem ocsp-update on
""")
        finding = check_ocsp_stapling(config)
        assert finding.check_id == "HAPR-TLS-010"
        assert finding.status == Status.PASS

    def test_fail_ssl_without_ocsp(self):
        config = parse_string("""
frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_ocsp_stapling(config)
        assert finding.check_id == "HAPR-TLS-010"
        assert finding.status == Status.FAIL

    def test_na_no_ssl_binds(self):
        config = parse_string("""
frontend ft_plain
    bind *:80
""")
        finding = check_ocsp_stapling(config)
        assert finding.check_id == "HAPR-TLS-010"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 2. HAPR-TLS-011: FIPS Ciphers
# ---------------------------------------------------------------------------

class TestFIPSCiphers:
    """Test check_fips_ciphers for HAPR-TLS-011."""

    def test_pass_fips_only_ciphers(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:DHE+AESGCM

frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_fips_ciphers(config)
        assert finding.check_id == "HAPR-TLS-011"
        assert finding.status == Status.PASS

    def test_partial_chacha20_cipher(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20

frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_fips_ciphers(config)
        assert finding.check_id == "HAPR-TLS-011"
        assert finding.status == Status.PARTIAL

    def test_fail_no_cipher_config_with_ssl(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_fips_ciphers(config)
        assert finding.check_id == "HAPR-TLS-011"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 3. HAPR-MTLS-001: mTLS Client Verification
# ---------------------------------------------------------------------------

class TestMTLSClientVerification:
    """Test check_mtls_client_verification for HAPR-MTLS-001."""

    def test_pass_verify_required_with_ca_file(self):
        config = parse_string("""
frontend ft_mtls
    bind *:443 ssl crt /cert.pem verify required ca-file /ca.pem
""")
        finding = check_mtls_client_verification(config)
        assert finding.check_id == "HAPR-MTLS-001"
        assert finding.status == Status.PASS

    def test_partial_verify_optional(self):
        config = parse_string("""
frontend ft_mtls
    bind *:443 ssl crt /cert.pem verify optional ca-file /ca.pem
""")
        finding = check_mtls_client_verification(config)
        assert finding.check_id == "HAPR-MTLS-001"
        assert finding.status == Status.PARTIAL

    def test_na_no_ssl_binds(self):
        config = parse_string("""
frontend ft_plain
    bind *:80
""")
        finding = check_mtls_client_verification(config)
        assert finding.check_id == "HAPR-MTLS-001"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 4. HAPR-MTLS-002: Client CRL Configured
# ---------------------------------------------------------------------------

class TestClientCRLConfigured:
    """Test check_client_crl_configured for HAPR-MTLS-002."""

    def test_pass_crl_file_present(self):
        config = parse_string("""
frontend ft_mtls
    bind *:443 ssl crt /cert.pem verify required ca-file /ca.pem crl-file /crl.pem
""")
        finding = check_client_crl_configured(config)
        assert finding.check_id == "HAPR-MTLS-002"
        assert finding.status == Status.PASS

    def test_fail_no_crl_file(self):
        config = parse_string("""
frontend ft_mtls
    bind *:443 ssl crt /cert.pem verify required ca-file /ca.pem
""")
        finding = check_client_crl_configured(config)
        assert finding.check_id == "HAPR-MTLS-002"
        assert finding.status == Status.FAIL

    def test_na_no_mtls_binds(self):
        config = parse_string("""
frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_client_crl_configured(config)
        assert finding.check_id == "HAPR-MTLS-002"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-TLS-001: Minimum TLS Version
# ---------------------------------------------------------------------------

class TestMinTLSVersion:
    """Test check_min_tls_version for HAPR-TLS-001."""

    def test_pass_global_ssl_min_ver_tls12(self):
        config = parse_string("""
global
    ssl-default-bind-options ssl-min-ver TLSv1.2
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.PASS

    def test_pass_global_ssl_min_ver_tls13(self):
        config = parse_string("""
global
    ssl-default-bind-options ssl-min-ver TLSv1.3
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.PASS

    def test_pass_all_binds_have_ssl_min_ver(self):
        config = parse_string("""
frontend ft1
    bind *:443 ssl crt /cert.pem ssl-min-ver TLSv1.2

frontend ft2
    bind *:8443 ssl crt /cert.pem ssl-min-ver TLSv1.2
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.PASS

    def test_partial_some_binds_have_ssl_min_ver(self):
        config = parse_string("""
frontend ft1
    bind *:443 ssl crt /cert.pem ssl-min-ver TLSv1.2

frontend ft2
    bind *:8443 ssl crt /cert.pem
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.PARTIAL

    def test_fail_weak_version_in_global(self):
        config = parse_string("""
global
    ssl-default-bind-options sslv3
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.FAIL

    def test_fail_no_enforcement(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.FAIL

    def test_fail_weak_ssl_min_ver_global(self):
        config = parse_string("""
global
    ssl-default-bind-options ssl-min-ver TLSv1.0
""")
        finding = check_min_tls_version(config)
        assert finding.check_id == "HAPR-TLS-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-003: SSL Default Bind Options Set
# ---------------------------------------------------------------------------

class TestSSLDefaultBindOptions:
    """Test check_ssl_default_bind_options for HAPR-TLS-003."""

    def test_pass_present(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
""")
        finding = check_ssl_default_bind_options(config)
        assert finding.check_id == "HAPR-TLS-003"
        assert finding.status == Status.PASS

    def test_fail_missing(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_ssl_default_bind_options(config)
        assert finding.check_id == "HAPR-TLS-003"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-004: SSL Default Bind Ciphers Set
# ---------------------------------------------------------------------------

class TestSSLDefaultBindCiphers:
    """Test check_ssl_default_bind_ciphers for HAPR-TLS-004."""

    def test_pass_present(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:DHE+AESGCM:!aNULL:!MD5
""")
        finding = check_ssl_default_bind_ciphers(config)
        assert finding.check_id == "HAPR-TLS-004"
        assert finding.status == Status.PASS

    def test_fail_missing(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_ssl_default_bind_ciphers(config)
        assert finding.check_id == "HAPR-TLS-004"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-005: TLS 1.3 Ciphersuites Configured
# ---------------------------------------------------------------------------

class TestTLS13Ciphersuites:
    """Test check_ssl_default_bind_ciphersuites for HAPR-TLS-005."""

    def test_pass_ciphersuites_present(self):
        config = parse_string("""
global
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
""")
        finding = check_ssl_default_bind_ciphersuites(config)
        assert finding.check_id == "HAPR-TLS-005"
        assert finding.status == Status.PASS

    def test_partial_only_tls12_ciphers(self):
        config = parse_string("""
global
    ssl-default-bind-ciphers ECDHE+AESGCM:DHE+AESGCM
""")
        finding = check_ssl_default_bind_ciphersuites(config)
        assert finding.check_id == "HAPR-TLS-005"
        assert finding.status == Status.PARTIAL

    def test_fail_no_cipher_config(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_ssl_default_bind_ciphersuites(config)
        assert finding.check_id == "HAPR-TLS-005"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-007: DH Parameter Size
# ---------------------------------------------------------------------------

class TestDHParamSize:
    """Test check_dh_param_size for HAPR-TLS-007."""

    def test_pass_dh_param_2048(self):
        config = parse_string("""
global
    tune.ssl.default-dh-param 2048
""")
        finding = check_dh_param_size(config)
        assert finding.check_id == "HAPR-TLS-007"
        assert finding.status == Status.PASS

    def test_pass_dh_param_4096(self):
        config = parse_string("""
global
    tune.ssl.default-dh-param 4096
""")
        finding = check_dh_param_size(config)
        assert finding.check_id == "HAPR-TLS-007"
        assert finding.status == Status.PASS

    def test_partial_dh_param_1024(self):
        config = parse_string("""
global
    tune.ssl.default-dh-param 1024
""")
        finding = check_dh_param_size(config)
        assert finding.check_id == "HAPR-TLS-007"
        assert finding.status == Status.PARTIAL

    def test_fail_dh_param_missing(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_dh_param_size(config)
        assert finding.check_id == "HAPR-TLS-007"
        assert finding.status == Status.FAIL

    def test_fail_dh_param_non_integer(self):
        config = parse_string("""
global
    tune.ssl.default-dh-param auto
""")
        finding = check_dh_param_size(config)
        assert finding.check_id == "HAPR-TLS-007"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TLS-008: TLS Session Tickets — additional PARTIAL paths
# ---------------------------------------------------------------------------

class TestTLSSessionTicketsPartial:
    """Additional PARTIAL path tests for check_tls_session_tickets_disabled."""

    def test_partial_all_binds_no_tls_tickets(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3

frontend ft1
    bind *:443 ssl crt /cert.pem no-tls-tickets

frontend ft2
    bind *:8443 ssl crt /cert.pem no-tls-tickets
""")
        finding = tls.check_tls_session_tickets_disabled(config)
        assert finding.check_id == "HAPR-TLS-008"
        assert finding.status == Status.PARTIAL

    def test_partial_some_binds_no_tls_tickets(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3

frontend ft1
    bind *:443 ssl crt /cert.pem no-tls-tickets

frontend ft2
    bind *:8443 ssl crt /cert.pem
""")
        finding = tls.check_tls_session_tickets_disabled(config)
        assert finding.check_id == "HAPR-TLS-008"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# HAPR-MTLS-001: mTLS Client Verification — additional paths
# ---------------------------------------------------------------------------

class TestMTLSClientVerificationAdditional:
    """Additional path tests for check_mtls_client_verification."""

    def test_fail_ssl_binds_no_verify(self):
        config = parse_string("""
frontend ft_ssl
    bind *:443 ssl crt /cert.pem
""")
        finding = check_mtls_client_verification(config)
        assert finding.check_id == "HAPR-MTLS-001"
        assert finding.status == Status.FAIL

    def test_partial_verify_required_without_ca_file(self):
        config = parse_string("""
frontend ft_mtls
    bind *:443 ssl crt /cert.pem verify required
""")
        finding = check_mtls_client_verification(config)
        assert finding.check_id == "HAPR-MTLS-001"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# HAPR-TLS-006: HSTS edge cases (backend, add-header)
# ---------------------------------------------------------------------------

class TestHSTSEdgeCases:
    """Test HSTS detection in backend sections and via add-header."""

    def test_hsts_in_backend_section_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Strict-Transport-Security max-age=31536000
    server web1 10.0.0.1:80 check
""")
        finding = check_hsts_configured(config)
        assert finding.check_id == "HAPR-TLS-006"
        assert finding.status == Status.PASS

    def test_hsts_via_add_header_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response add-header Strict-Transport-Security max-age=31536000
""")
        finding = check_hsts_configured(config)
        assert finding.check_id == "HAPR-TLS-006"
        assert finding.status == Status.PASS

    def test_hsts_via_add_header_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response add-header Strict-Transport-Security max-age=31536000
    server web1 10.0.0.1:80 check
""")
        finding = check_hsts_configured(config)
        assert finding.check_id == "HAPR-TLS-006"
        assert finding.status == Status.PASS


# ===========================================================================
# Issue #20: TLS — force-tlsv12 and no-sslv3/no-tlsv10/no-tlsv11
# ===========================================================================

class TestMinTLSVersionAlternatives:
    """check_min_tls_version should recognise force-tlsv12 and no-ssl/tls combos."""

    def test_force_tlsv12_pass(self):
        config = parse_string("""
global
    ssl-default-bind-options force-tlsv12
""")
        finding = check_min_tls_version(config)
        assert finding.status == Status.PASS

    def test_no_ssl_tls_combo_pass(self):
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
""")
        finding = check_min_tls_version(config)
        assert finding.status == Status.PASS

    def test_incomplete_no_combo_fail(self):
        """Only no-sslv3 and no-tlsv10 — missing no-tlsv11."""
        config = parse_string("""
global
    ssl-default-bind-options no-sslv3 no-tlsv10
""")
        finding = check_min_tls_version(config)
        assert finding.status == Status.FAIL


# ===========================================================================
# Issue #21: TLS — ssl-dh-param-file
# ===========================================================================

class TestDHParamFile:
    """check_dh_param_size should recognise ssl-dh-param-file."""

    def test_dh_param_file_pass(self):
        config = parse_string("""
global
    ssl-dh-param-file /etc/haproxy/dhparams.pem
""")
        finding = check_dh_param_size(config)
        assert finding.status == Status.PASS
        assert "ssl-dh-param-file" in finding.evidence

    def test_numeric_dh_param_still_works(self):
        config = parse_string("""
global
    tune.ssl.default-dh-param 2048
""")
        finding = check_dh_param_size(config)
        assert finding.status == Status.PASS


# ===========================================================================
# Issue #29: TLS — no ciphers configured → PARTIAL
# ===========================================================================

class TestNoCiphersConfigured:
    """check_no_weak_ciphers should return PARTIAL when no ciphers are configured."""

    def test_no_ciphers_partial(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_https
    bind :443 ssl crt /cert.pem
""")
        finding = check_no_weak_ciphers(config)
        assert finding.status == Status.PARTIAL
        assert "No explicit cipher" in finding.message
