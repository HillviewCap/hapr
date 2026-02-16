"""Tests for backend check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks.backend import (
    check_backend_ssl,
    check_backend_ssl_verification,
    check_cache_security,
    check_health_checks,
    check_connection_limits,
    check_cookie_security,
    check_retry_redispatch,
)


# ---------------------------------------------------------------------------
# Fix 5: Backend SSL verify none detection
# ---------------------------------------------------------------------------

class TestBackendSSLVerifyNone:
    """Test detection of ssl verify none on backend servers."""

    def test_ssl_verify_none_returns_partial(self):
        config = parse_string("""
backend bk_api
    server api1 10.0.0.1:443 ssl verify none
""")
        finding = check_backend_ssl(config)
        assert finding.status == Status.PARTIAL
        assert "verify" in finding.evidence.lower() or "Verify disabled" in finding.evidence

    def test_ssl_verify_required_passes(self):
        config = parse_string("""
backend bk_api
    server api1 10.0.0.1:443 ssl verify required ca-file /etc/ssl/certs/ca-bundle.crt
""")
        finding = check_backend_ssl(config)
        assert finding.status == Status.PASS

    def test_ssl_without_verify_passes(self):
        """SSL without explicit verify option should still pass."""
        config = parse_string("""
backend bk_api
    server api1 10.0.0.1:443 ssl
""")
        finding = check_backend_ssl(config)
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-BKD-006: Backend SSL verification
# ---------------------------------------------------------------------------

class TestBackendSSLVerification:
    """Test check_backend_ssl_verification for HAPR-BKD-006."""

    def test_ssl_verify_required_with_ca_file_passes(self):
        config = parse_string("""
backend bk_api
    server web1 10.0.0.1:443 ssl verify required ca-file /etc/ssl/ca.crt
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.PASS

    def test_ssl_verify_none_fails(self):
        config = parse_string("""
backend bk_api
    server web1 10.0.0.1:443 ssl verify none
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.FAIL

    def test_no_ssl_returns_na(self):
        config = parse_string("""
backend bk_api
    server web1 10.0.0.1:80
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 16. HAPR-CACHE-001: Cache Security
# ---------------------------------------------------------------------------

class TestCacheSecurity:
    """Test check_cache_security for HAPR-CACHE-001."""

    def test_pass_cache_with_controls(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_web
    bind *:80
    http-request cache-use my_cache
    http-response cache-store my_cache
    total-max-size 64
    max-age 3600
    default_backend bk_web
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.PASS

    def test_fail_cache_without_controls(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request cache-use my_cache
    http-response cache-store my_cache
    default_backend bk_web
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.FAIL

    def test_na_no_cache(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-BKD-001: Health Checks Configured
# ---------------------------------------------------------------------------

class TestHealthChecks:
    """Test check_health_checks for HAPR-BKD-001."""

    def test_pass_all_backends_have_check(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check
    server web2 10.0.0.2:80 check

backend bk_api
    option httpchk GET /health
    server api1 10.0.0.3:8080 check
""")
        finding = check_health_checks(config)
        assert finding.check_id == "HAPR-BKD-001"
        assert finding.status == Status.PASS

    def test_partial_some_backends_missing_check(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check

backend bk_api
    server api1 10.0.0.3:8080
""")
        finding = check_health_checks(config)
        assert finding.check_id == "HAPR-BKD-001"
        assert finding.status == Status.PARTIAL

    def test_fail_no_checks(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80
    server web2 10.0.0.2:80
""")
        finding = check_health_checks(config)
        assert finding.check_id == "HAPR-BKD-001"
        assert finding.status == Status.FAIL

    def test_na_no_backends(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_health_checks(config)
        assert finding.check_id == "HAPR-BKD-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_listen_section_with_check(self):
        config = parse_string("""
listen my_app
    bind *:80
    server web1 10.0.0.1:80 check
""")
        finding = check_health_checks(config)
        assert finding.check_id == "HAPR-BKD-001"
        assert finding.status == Status.PASS


class TestBackendConnectionLimits:
    """Test check_connection_limits for HAPR-BKD-002."""

    def test_pass_maxconn_on_servers(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check maxconn 500
""")
        finding = check_connection_limits(config)
        assert finding.check_id == "HAPR-BKD-002"
        assert finding.status == Status.PASS

    def test_pass_fullconn_directive(self):
        config = parse_string("""
backend bk_web
    fullconn 1000
    server web1 10.0.0.1:80 check
""")
        finding = check_connection_limits(config)
        assert finding.check_id == "HAPR-BKD-002"
        assert finding.status == Status.PASS

    def test_fail_no_limits(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check
""")
        finding = check_connection_limits(config)
        assert finding.check_id == "HAPR-BKD-002"
        assert finding.status == Status.FAIL

    def test_na_no_backends(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_connection_limits(config)
        assert finding.check_id == "HAPR-BKD-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_listen_section(self):
        config = parse_string("""
listen my_app
    bind *:80
    server web1 10.0.0.1:80 check maxconn 500
""")
        finding = check_connection_limits(config)
        assert finding.check_id == "HAPR-BKD-002"
        assert finding.status == Status.PASS


class TestBackendSSLAdditional:
    """Additional tests for check_backend_ssl (HAPR-BKD-003)."""

    def test_fail_no_ssl(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check
""")
        finding = check_backend_ssl(config)
        assert finding.check_id == "HAPR-BKD-003"
        assert finding.status == Status.FAIL

    def test_partial_mixed_ssl_and_non_ssl(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:443 ssl check
    server web2 10.0.0.2:80 check
""")
        finding = check_backend_ssl(config)
        assert finding.check_id == "HAPR-BKD-003"
        assert finding.status == Status.PARTIAL

    def test_na_no_servers(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_backend_ssl(config)
        assert finding.check_id == "HAPR-BKD-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_partial_verify_none_with_non_ssl(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:443 ssl verify none check
    server web2 10.0.0.2:80 check
""")
        finding = check_backend_ssl(config)
        assert finding.check_id == "HAPR-BKD-003"
        assert finding.status == Status.PARTIAL


class TestCookieSecurity:
    """Test check_cookie_security for HAPR-BKD-004."""

    def test_pass_fully_secured(self):
        config = parse_string("""
backend bk_web
    cookie SERVERID insert indirect nocache httponly secure attr SameSite=Strict
    server web1 10.0.0.1:80 check cookie srv1
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.PASS

    def test_partial_missing_samesite(self):
        config = parse_string("""
backend bk_web
    cookie SERVERID insert indirect nocache httponly secure
    server web1 10.0.0.1:80 check cookie srv1
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.PARTIAL

    def test_partial_missing_secure(self):
        config = parse_string("""
backend bk_web
    cookie SERVERID insert indirect nocache httponly attr SameSite=Strict
    server web1 10.0.0.1:80 check cookie srv1
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.PARTIAL

    def test_fail_no_security_attrs(self):
        config = parse_string("""
backend bk_web
    cookie SERVERID insert indirect nocache
    server web1 10.0.0.1:80 check cookie srv1
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.FAIL

    def test_na_no_cookie(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.NOT_APPLICABLE

    def test_na_no_backends(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_cookie_security(config)
        assert finding.check_id == "HAPR-BKD-004"
        assert finding.status == Status.NOT_APPLICABLE


class TestRetryRedispatch:
    """Test check_retry_redispatch for HAPR-BKD-005."""

    def test_pass_defaults_both(self):
        config = parse_string("""
defaults
    retries 3
    option redispatch
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.PASS

    def test_pass_backend_both(self):
        config = parse_string("""
backend bk_web
    retries 3
    option redispatch
    server web1 10.0.0.1:80 check
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.PASS

    def test_partial_retries_only(self):
        config = parse_string("""
defaults
    retries 3
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.PARTIAL

    def test_partial_redispatch_only(self):
        config = parse_string("""
defaults
    option redispatch
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.PARTIAL

    def test_fail_neither(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.FAIL

    def test_pass_mixed_defaults_and_backend(self):
        config = parse_string("""
defaults
    retries 3

backend bk_web
    option redispatch
    server web1 10.0.0.1:80 check
""")
        finding = check_retry_redispatch(config)
        assert finding.check_id == "HAPR-BKD-005"
        assert finding.status == Status.PASS


class TestBackendSSLVerificationAdditional:
    """Additional tests for check_backend_ssl_verification (HAPR-BKD-006)."""

    def test_partial_no_ca_file(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:443 ssl verify required check
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.PARTIAL

    def test_partial_mixed(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:443 ssl verify required ca-file /etc/ssl/ca.pem check
    server web2 10.0.0.2:443 ssl check
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.PARTIAL

    def test_fail_no_verify(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:443 ssl check
""")
        finding = check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.FAIL


class TestCacheSecurityAdditional:
    """Additional tests for check_cache_security (HAPR-CACHE-001)."""

    def test_partial_only_total_max_size(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request cache-use my_cache
    http-response cache-store my_cache
    total-max-size 64
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.PARTIAL

    def test_partial_only_max_age(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request cache-use my_cache
    http-response cache-store my_cache
    max-age 3600
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.PARTIAL

    def test_pass_cache_in_backend(self):
        config = parse_string("""
backend bk_web
    http-request cache-use my_cache
    http-response cache-store my_cache
    total-max-size 64
    max-age 3600
    server web1 10.0.0.1:80 check
""")
        finding = check_cache_security(config)
        assert finding.check_id == "HAPR-CACHE-001"
        assert finding.status == Status.PASS
