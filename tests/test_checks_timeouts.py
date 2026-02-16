"""Tests for timeout check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks.timeouts import (
    check_client_timeout,
    check_server_timeout,
    check_connect_timeout,
    check_http_request_timeout,
    check_timeout_values_reasonable,
    check_http_keepalive_timeout,
)


# ---------------------------------------------------------------------------
# HAPR-TMO-006: HTTP keep-alive timeout
# ---------------------------------------------------------------------------

class TestHTTPKeepaliveTimeout:
    """Test check_http_keepalive_timeout for HAPR-TMO-006."""

    def test_http_keep_alive_timeout_present_passes(self):
        config = parse_string("""
defaults
    timeout http-keep-alive 5s
""")
        finding = check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.PASS

    def test_http_keep_alive_timeout_missing_fails(self):
        config = parse_string("""
defaults
    timeout client 30s
""")
        finding = check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-TMO-001: Client Timeout
# ---------------------------------------------------------------------------

class TestClientTimeout:
    """Test check_client_timeout for HAPR-TMO-001."""

    def test_pass_client_timeout_in_defaults(self):
        config = parse_string("""
defaults
    timeout client 30s
""")
        finding = check_client_timeout(config)
        assert finding.check_id == "HAPR-TMO-001"
        assert finding.status == Status.PASS

    def test_fail_client_timeout_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_client_timeout(config)
        assert finding.check_id == "HAPR-TMO-001"
        assert finding.status == Status.FAIL

    def test_pass_client_timeout_in_global(self):
        config = parse_string("""
global
    timeout client 30s
""")
        finding = check_client_timeout(config)
        assert finding.check_id == "HAPR-TMO-001"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-TMO-002: Server Timeout
# ---------------------------------------------------------------------------

class TestServerTimeout:
    """Test check_server_timeout for HAPR-TMO-002."""

    def test_pass_server_timeout_in_defaults(self):
        config = parse_string("""
defaults
    timeout server 30s
""")
        finding = check_server_timeout(config)
        assert finding.check_id == "HAPR-TMO-002"
        assert finding.status == Status.PASS

    def test_fail_server_timeout_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_server_timeout(config)
        assert finding.check_id == "HAPR-TMO-002"
        assert finding.status == Status.FAIL

    def test_pass_server_timeout_in_backend(self):
        """Server timeout set in backend should now be found (bug fix)."""
        config = parse_string("""
backend bk_web
    timeout server 30s
    server web1 10.0.0.1:80 check
""")
        finding = check_server_timeout(config)
        assert finding.check_id == "HAPR-TMO-002"
        assert finding.status == Status.PASS
        assert "backend" in finding.evidence.lower()


# ---------------------------------------------------------------------------
# HAPR-TMO-003: Connect Timeout
# ---------------------------------------------------------------------------

class TestConnectTimeout:
    """Test check_connect_timeout for HAPR-TMO-003."""

    def test_pass_connect_timeout_in_defaults(self):
        config = parse_string("""
defaults
    timeout connect 5s
""")
        finding = check_connect_timeout(config)
        assert finding.check_id == "HAPR-TMO-003"
        assert finding.status == Status.PASS

    def test_fail_connect_timeout_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_connect_timeout(config)
        assert finding.check_id == "HAPR-TMO-003"
        assert finding.status == Status.FAIL

    def test_pass_connect_timeout_in_backend(self):
        """Connect timeout set in backend should now be found (bug fix)."""
        config = parse_string("""
backend bk_web
    timeout connect 5s
    server web1 10.0.0.1:80 check
""")
        finding = check_connect_timeout(config)
        assert finding.check_id == "HAPR-TMO-003"
        assert finding.status == Status.PASS
        assert "backend" in finding.evidence.lower()


# ---------------------------------------------------------------------------
# HAPR-TMO-004: HTTP Request Timeout
# ---------------------------------------------------------------------------

class TestHttpRequestTimeout:
    """Test check_http_request_timeout for HAPR-TMO-004."""

    def test_pass_http_request_timeout_in_defaults(self):
        config = parse_string("""
defaults
    timeout http-request 10s
""")
        finding = check_http_request_timeout(config)
        assert finding.check_id == "HAPR-TMO-004"
        assert finding.status == Status.PASS

    def test_fail_http_request_timeout_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_http_request_timeout(config)
        assert finding.check_id == "HAPR-TMO-004"
        assert finding.status == Status.FAIL

    def test_pass_http_request_timeout_in_frontend(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    timeout http-request 10s
    default_backend bk_web
""")
        finding = check_http_request_timeout(config)
        assert finding.check_id == "HAPR-TMO-004"
        assert finding.status == Status.PASS

    def test_pass_http_request_timeout_in_listen(self):
        config = parse_string("""
listen app
    bind *:80
    timeout http-request 10s
    server web1 10.0.0.1:80 check
""")
        finding = check_http_request_timeout(config)
        assert finding.check_id == "HAPR-TMO-004"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-TMO-005: Timeout Values Reasonable
# ---------------------------------------------------------------------------

class TestTimeoutValuesReasonable:
    """Test check_timeout_values_reasonable for HAPR-TMO-005."""

    def test_pass_all_reasonable(self):
        config = parse_string("""
defaults
    timeout client 30s
    timeout server 30s
    timeout connect 5s
    timeout http-request 10s
""")
        finding = check_timeout_values_reasonable(config)
        assert finding.check_id == "HAPR-TMO-005"
        assert finding.status == Status.PASS

    def test_fail_extreme_value(self):
        config = parse_string("""
defaults
    timeout client 1h
    timeout server 30s
    timeout connect 5s
    timeout http-request 10s
""")
        finding = check_timeout_values_reasonable(config)
        assert finding.check_id == "HAPR-TMO-005"
        assert finding.status == Status.FAIL

    def test_partial_too_long(self):
        config = parse_string("""
defaults
    timeout client 8m
    timeout server 30s
    timeout connect 5s
    timeout http-request 10s
""")
        finding = check_timeout_values_reasonable(config)
        assert finding.check_id == "HAPR-TMO-005"
        assert finding.status == Status.PARTIAL

    def test_fail_all_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_timeout_values_reasonable(config)
        assert finding.check_id == "HAPR-TMO-005"
        assert finding.status == Status.FAIL

    def test_partial_some_missing(self):
        config = parse_string("""
defaults
    timeout client 30s
    timeout server 30s
""")
        finding = check_timeout_values_reasonable(config)
        assert finding.check_id == "HAPR-TMO-005"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# HAPR-TMO-006: HTTP Keep-Alive Timeout - Extended
# ---------------------------------------------------------------------------

class TestHTTPKeepaliveTimeoutExtended:
    """Extended tests for check_http_keepalive_timeout (HAPR-TMO-006)."""

    def test_pass_keepalive_in_frontend(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    timeout http-keep-alive 5s
    default_backend bk_web
""")
        finding = check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.PASS

    def test_pass_keepalive_in_listen(self):
        config = parse_string("""
listen app
    bind *:80
    timeout http-keep-alive 5s
    server web1 10.0.0.1:80 check
""")
        finding = check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.PASS
