"""Tests for request check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import request
from hapr.framework.checks.request import (
    check_max_body_size,
    check_url_length_limits,
    check_method_filtering,
    check_request_header_limits,
    check_http_smuggling_prevention,
    check_h2_stream_limits,
    check_h2c_smuggling_prevention,
)


# ---------------------------------------------------------------------------
# Phase 2: REQ-002 and REQ-004 false positive fixes
# ---------------------------------------------------------------------------

class TestREQFixedFalsePositives:
    """Tests for Phase 2 REQ-002 and REQ-004 false positive fixes."""

    def test_req002_tune_maxrewrite_alone_not_pass(self):
        config = parse_string("""
global
    tune.maxrewrite 1024
""")
        finding = request.check_url_length_limits(config)
        assert finding.status == Status.FAIL

    def test_req004_tune_http_maxhdr_passes(self):
        config = parse_string("""
global
    tune.http.maxhdr 101
""")
        finding = request.check_request_header_limits(config)
        assert finding.status == Status.PASS

    def test_req004_tune_bufsize_alone_partial(self):
        config = parse_string("""
global
    tune.bufsize 16384
""")
        finding = request.check_request_header_limits(config)
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# HAPR-REQ-005: HTTP smuggling prevention
# ---------------------------------------------------------------------------

class TestHTTPSmugglingPrevention:
    """Test check_http_smuggling_prevention for HAPR-REQ-005."""

    def test_content_length_deny_rule_passes(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny deny_status 400 if { req.hdr_cnt(content-length) gt 1 }
    default_backend bk_web
""")
        finding = request.check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_option_httpclose_passes(self):
        config = parse_string("""
defaults
    mode http
    option httpclose
""")
        finding = request.check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_no_smuggling_prevention_fails(self):
        config = parse_string("""
defaults
    mode http

frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = request.check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 17. HAPR-H2-001: H2 Stream Limits
# ---------------------------------------------------------------------------

class TestH2StreamLimits:
    """Test check_h2_stream_limits for HAPR-H2-001."""

    def test_pass_h2_with_stream_limits(self):
        config = parse_string("""
global
    tune.h2.max-concurrent-streams 100

frontend ft_ssl
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.PASS

    def test_fail_h2_without_stream_limits(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_ssl
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.FAIL

    def test_na_no_h2_binds(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 18. HAPR-H2-002: H2C Smuggling Prevention
# ---------------------------------------------------------------------------

class TestH2CSmugglingPrevention:
    """Test check_h2c_smuggling_prevention for HAPR-H2-002."""

    def test_pass_h2_only_over_ssl(self):
        config = parse_string("""
frontend ft_ssl
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.PASS

    def test_fail_non_ssl_h2_without_deny(self):
        config = parse_string("""
frontend ft_plain
    bind *:80 proto h2
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.FAIL

    def test_na_no_h2(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-REQ-001: Maximum Request Body Size Limited
# ---------------------------------------------------------------------------

class TestMaxBodySize:
    """Test check_max_body_size for HAPR-REQ-001."""

    def test_pass_body_size_deny_rule(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny deny_status 413 if { req.body_size gt 10485760 }
    default_backend bk_web
""")
        finding = check_max_body_size(config)
        assert finding.check_id == "HAPR-REQ-001"
        assert finding.status == Status.PASS

    def test_pass_tune_bufsize(self):
        config = parse_string("""
global
    tune.bufsize 16384
""")
        finding = check_max_body_size(config)
        assert finding.check_id == "HAPR-REQ-001"
        assert finding.status == Status.PASS

    def test_pass_http_buffer_request_with_bufsize(self):
        config = parse_string("""
global
    tune.bufsize 16384

frontend ft_web
    bind *:80
    option http-buffer-request
    default_backend bk_web
""")
        finding = check_max_body_size(config)
        assert finding.check_id == "HAPR-REQ-001"
        assert finding.status == Status.PASS

    def test_fail_no_body_limits(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_max_body_size(config)
        assert finding.check_id == "HAPR-REQ-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-REQ-002: URL Length Limits
# ---------------------------------------------------------------------------

class TestURLLengthLimits:
    """Test check_url_length_limits for HAPR-REQ-002."""

    def test_pass_url_len_deny_rule(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny deny_status 414 if { url_len gt 8192 }
    default_backend bk_web
""")
        finding = check_url_length_limits(config)
        assert finding.check_id == "HAPR-REQ-002"
        assert finding.status == Status.PASS

    def test_pass_path_len_deny_rule(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny deny_status 414 if { path_len gt 4096 }
    default_backend bk_web
""")
        finding = check_url_length_limits(config)
        assert finding.check_id == "HAPR-REQ-002"
        assert finding.status == Status.PASS

    def test_pass_tune_http_maxuri(self):
        config = parse_string("""
global
    tune.http.maxuri 8192
""")
        finding = check_url_length_limits(config)
        assert finding.check_id == "HAPR-REQ-002"
        assert finding.status == Status.PASS

    def test_fail_no_url_limits(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_url_length_limits(config)
        assert finding.check_id == "HAPR-REQ-002"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-REQ-003: HTTP Method Filtering
# ---------------------------------------------------------------------------

class TestMethodFiltering:
    """Test check_method_filtering for HAPR-REQ-003."""

    def test_pass_method_deny_rule(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny if !{ method GET } !{ method POST } !{ method HEAD }
    default_backend bk_web
""")
        finding = check_method_filtering(config)
        assert finding.check_id == "HAPR-REQ-003"
        assert finding.status == Status.PASS

    def test_pass_method_acl_with_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl valid_method method GET HEAD POST
    http-request deny if !valid_method
    default_backend bk_web
""")
        finding = check_method_filtering(config)
        assert finding.check_id == "HAPR-REQ-003"
        assert finding.status == Status.PASS

    def test_pass_method_deny_in_backend(self):
        config = parse_string("""
backend bk_web
    http-request deny if !{ method GET } !{ method POST }
    server web1 10.0.0.1:80 check
""")
        finding = check_method_filtering(config)
        assert finding.check_id == "HAPR-REQ-003"
        assert finding.status == Status.PASS

    def test_fail_no_method_filtering(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_method_filtering(config)
        assert finding.check_id == "HAPR-REQ-003"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-REQ-004: Request Header Size Limits
# ---------------------------------------------------------------------------

class TestRequestHeaderLimits:
    """Test check_request_header_limits for HAPR-REQ-004."""

    def test_pass_maxhdr_set(self):
        config = parse_string("""
global
    tune.http.maxhdr 101
""")
        finding = check_request_header_limits(config)
        assert finding.check_id == "HAPR-REQ-004"
        assert finding.status == Status.PASS

    def test_pass_maxhdr_and_bufsize(self):
        config = parse_string("""
global
    tune.http.maxhdr 101
    tune.bufsize 16384
""")
        finding = check_request_header_limits(config)
        assert finding.check_id == "HAPR-REQ-004"
        assert finding.status == Status.PASS

    def test_partial_only_bufsize(self):
        config = parse_string("""
global
    tune.bufsize 16384
""")
        finding = check_request_header_limits(config)
        assert finding.check_id == "HAPR-REQ-004"
        assert finding.status == Status.PARTIAL

    def test_fail_no_header_limits(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_request_header_limits(config)
        assert finding.check_id == "HAPR-REQ-004"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-REQ-005: HTTP Request Smuggling Prevention
# ---------------------------------------------------------------------------

class TestHTTPSmugglingPreventionExtended:
    """Test check_http_smuggling_prevention for HAPR-REQ-005."""

    def test_pass_option_httpclose(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    option httpclose
    default_backend bk_web
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_duplicate_cl_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    default_backend bk_web
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_duplicate_te_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
    default_backend bk_web
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_http_use_htx(self):
        config = parse_string("""
global
    option http-use-htx
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_restrict_req_hdr_names(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    option http-restrict-req-hdr-names reject
    default_backend bk_web
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_fail_no_smuggling_prevention(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.FAIL

    def test_pass_smuggling_prevention_in_backend(self):
        """Bug fix: backend sections are now included in smuggling check."""
        config = parse_string("""
backend bk_web
    option httpclose
    server web1 10.0.0.1:80 check
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_cl_deny_in_backend(self):
        """Bug fix: duplicate CL deny rule in backend is detected."""
        config = parse_string("""
backend bk_web
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    server web1 10.0.0.1:80 check
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_te_deny_in_backend(self):
        """Bug fix: duplicate TE deny rule in backend is detected."""
        config = parse_string("""
backend bk_web
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
    server web1 10.0.0.1:80 check
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS

    def test_pass_smuggling_prevention_in_defaults(self):
        config = parse_string("""
defaults
    option httpclose
""")
        finding = check_http_smuggling_prevention(config)
        assert finding.check_id == "HAPR-REQ-005"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-H2-001: HTTP/2 Stream Limits
# ---------------------------------------------------------------------------

class TestH2StreamLimitsExtended:
    """Test check_h2_stream_limits for HAPR-H2-001."""

    def test_na_no_h2_binds(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_h2_with_stream_limits(self):
        config = parse_string("""
global
    tune.h2.max-concurrent-streams 100

frontend ft_web
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.PASS

    def test_fail_h2_without_stream_limits(self):
        config = parse_string("""
frontend ft_web
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2_stream_limits(config)
        assert finding.check_id == "HAPR-H2-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-H2-002: H2C Smuggling Prevention
# ---------------------------------------------------------------------------

class TestH2CSmugglingPreventionExtended:
    """Test check_h2c_smuggling_prevention for HAPR-H2-002."""

    def test_na_no_h2_binds(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_h2_over_ssl_only(self):
        config = parse_string("""
frontend ft_web
    bind *:443 ssl crt /cert.pem alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.PASS

    def test_fail_h2c_without_protection(self):
        config = parse_string("""
frontend ft_web
    bind *:80 alpn h2,http/1.1
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.FAIL

    def test_partial_h2c_with_deny_rule(self):
        config = parse_string("""
frontend ft_web
    bind *:80 alpn h2,http/1.1
    http-request deny if { req.hdr(upgrade) -i h2c }
    default_backend bk_web
""")
        finding = check_h2c_smuggling_prevention(config)
        assert finding.check_id == "HAPR-H2-002"
        assert finding.status == Status.PARTIAL
