"""Tests for HTTP header check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import headers
from hapr.framework.checks.headers import (
    check_x_frame_options,
    check_x_content_type_options,
    check_cross_origin_resource_policy,
)
from hapr.framework.checks.tls import check_hsts_configured


class TestHeaderValueValidation:
    """Tests for Phase 2 header value validation."""

    def test_x_frame_options_deny_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Frame-Options DENY
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_x_frame_options_sameorigin_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Frame-Options SAMEORIGIN
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_x_frame_options_invalid_value_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Frame-Options ALLOWALL
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PARTIAL

    def test_x_frame_options_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.FAIL

    def test_x_content_type_nosniff_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Content-Type-Options nosniff
""")
        finding = headers.check_x_content_type_options(config)
        assert finding.status == Status.PASS

    def test_x_content_type_wrong_value_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Content-Type-Options nofollow
""")
        finding = headers.check_x_content_type_options(config)
        assert finding.status == Status.PARTIAL

    def test_x_content_type_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_x_content_type_options(config)
        assert finding.status == Status.FAIL

    def test_csp_with_unsafe_inline_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Content-Security-Policy "default-src 'self' 'unsafe-inline'"
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PARTIAL

    def test_csp_with_unsafe_eval_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Content-Security-Policy "default-src 'self' 'unsafe-eval'"
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PARTIAL

    def test_csp_with_wildcard_source_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Content-Security-Policy "default-src *"
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PARTIAL

    def test_csp_strict_policy_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self'"
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PASS

    def test_csp_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.FAIL

    def test_referrer_policy_unsafe_url_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Referrer-Policy unsafe-url
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.PARTIAL

    def test_referrer_policy_strict_origin_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Referrer-Policy strict-origin-when-cross-origin
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.PASS

    def test_referrer_policy_no_referrer_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Referrer-Policy no-referrer
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.PASS

    def test_referrer_policy_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-HDR-007: Cross-Origin-Opener-Policy
# ---------------------------------------------------------------------------

class TestCOOPHeader:
    """Test check_cross_origin_opener_policy for HAPR-HDR-007."""

    def test_coop_header_set_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Cross-Origin-Opener-Policy same-origin
""")
        finding = headers.check_cross_origin_opener_policy(config)
        assert finding.check_id == "HAPR-HDR-007"
        assert finding.status == Status.PASS

    def test_coop_header_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_cross_origin_opener_policy(config)
        assert finding.check_id == "HAPR-HDR-007"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-HDR-008: Cross-Origin-Embedder-Policy
# ---------------------------------------------------------------------------

class TestCOEPHeader:
    """Test check_cross_origin_embedder_policy for HAPR-HDR-008."""

    def test_coep_header_set_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Cross-Origin-Embedder-Policy require-corp
""")
        finding = headers.check_cross_origin_embedder_policy(config)
        assert finding.check_id == "HAPR-HDR-008"
        assert finding.status == Status.PASS

    def test_coep_header_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_cross_origin_embedder_policy(config)
        assert finding.check_id == "HAPR-HDR-008"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 12. HAPR-HDR-009: Cross-Origin-Resource-Policy Header
# ---------------------------------------------------------------------------

class TestCORPHeader:
    """Test check_cross_origin_resource_policy for HAPR-HDR-009."""

    def test_pass_corp_header_set(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Cross-Origin-Resource-Policy same-origin
""")
        finding = check_cross_origin_resource_policy(config)
        assert finding.check_id == "HAPR-HDR-009"
        assert finding.status == Status.PASS

    def test_fail_corp_header_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_cross_origin_resource_policy(config)
        assert finding.check_id == "HAPR-HDR-009"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-HDR-005: Permissions-Policy
# ---------------------------------------------------------------------------

class TestPermissionsPolicyHeader:
    """Test check_permissions_policy for HAPR-HDR-005."""

    def test_permissions_policy_set_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header Permissions-Policy "camera=(), microphone=(), geolocation=()"
""")
        finding = headers.check_permissions_policy(config)
        assert finding.check_id == "HAPR-HDR-005"
        assert finding.status == Status.PASS

    def test_permissions_policy_missing_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_permissions_policy(config)
        assert finding.check_id == "HAPR-HDR-005"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-HDR-006: X-XSS-Protection
# ---------------------------------------------------------------------------

class TestXXSSProtectionHeader:
    """Test check_x_xss_protection for HAPR-HDR-006."""

    def test_x_xss_protection_absent_passes(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.check_id == "HAPR-HDR-006"
        assert finding.status == Status.PASS

    def test_x_xss_protection_zero_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-XSS-Protection 0
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.check_id == "HAPR-HDR-006"
        assert finding.status == Status.PASS

    def test_x_xss_protection_quoted_zero_passes(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-XSS-Protection "0"
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.check_id == "HAPR-HDR-006"
        assert finding.status == Status.PASS

    def test_x_xss_protection_one_mode_block_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-XSS-Protection "1; mode=block"
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.check_id == "HAPR-HDR-006"
        assert finding.status == Status.PARTIAL

    def test_x_xss_protection_one_partial(self):
        config = parse_string("""
defaults
    mode http
    http-response set-header X-XSS-Protection 1
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.check_id == "HAPR-HDR-006"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# Header checks: backend section detection
# ---------------------------------------------------------------------------

class TestHeadersInBackendSection:
    """Verify headers set in backend sections are correctly detected.

    Validates the fix to _find_response_header() that adds config.backends
    to the search list.
    """

    def test_x_frame_options_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header X-Frame-Options DENY
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_csp_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Content-Security-Policy "default-src 'self'"
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PASS

    def test_x_content_type_options_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header X-Content-Type-Options nosniff
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_x_content_type_options(config)
        assert finding.status == Status.PASS

    def test_referrer_policy_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Referrer-Policy no-referrer
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.PASS

    def test_permissions_policy_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Permissions-Policy "camera=()"
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_permissions_policy(config)
        assert finding.status == Status.PASS

    def test_coop_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Cross-Origin-Opener-Policy same-origin
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_cross_origin_opener_policy(config)
        assert finding.status == Status.PASS

    def test_coep_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Cross-Origin-Embedder-Policy require-corp
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_cross_origin_embedder_policy(config)
        assert finding.status == Status.PASS

    def test_corp_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header Cross-Origin-Resource-Policy same-origin
    server srv1 127.0.0.1:8080
""")
        finding = check_cross_origin_resource_policy(config)
        assert finding.status == Status.PASS

    def test_x_xss_protection_zero_in_backend_passes(self):
        config = parse_string("""
backend bk_web
    mode http
    http-response set-header X-XSS-Protection 0
    server srv1 127.0.0.1:8080
""")
        finding = headers.check_x_xss_protection(config)
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# Header checks: edge cases
# ---------------------------------------------------------------------------

class TestHeaderEdgeCases:
    """Edge-case tests for header detection and value extraction."""

    def test_add_header_variant_detected(self):
        """http-response add-header should be detected, not just set-header."""
        config = parse_string("""
defaults
    mode http
    http-response add-header X-Frame-Options DENY
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_header_in_listen_section(self):
        """Headers in listen sections should be detected."""
        config = parse_string("""
listen stats
    mode http
    bind *:8404
    http-response set-header X-Content-Type-Options nosniff
""")
        finding = headers.check_x_content_type_options(config)
        assert finding.status == Status.PASS

    def test_header_in_frontend_section(self):
        """Headers in frontend sections should be detected."""
        config = parse_string("""
frontend ft_web
    mode http
    bind *:443
    http-response set-header Referrer-Policy strict-origin-when-cross-origin
    default_backend bk_web
""")
        finding = headers.check_referrer_policy(config)
        assert finding.status == Status.PASS

    def test_quoted_header_value(self):
        """Quoted header values should be stripped and matched correctly."""
        config = parse_string("""
defaults
    mode http
    http-response set-header X-Frame-Options "DENY"
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_case_insensitive_header_name(self):
        """Header name matching should be case-insensitive."""
        config = parse_string("""
defaults
    mode http
    http-response set-header x-frame-options DENY
""")
        finding = headers.check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_csp_multiple_dangerous_patterns(self):
        """CSP with multiple dangerous patterns should still be PARTIAL."""
        config = parse_string("""
defaults
    mode http
    http-response set-header Content-Security-Policy "default-src * 'unsafe-inline' 'unsafe-eval'"
""")
        finding = headers.check_csp_header(config)
        assert finding.status == Status.PARTIAL
        assert "unsafe-inline" in finding.message
        assert "unsafe-eval" in finding.message
        assert "wildcard" in finding.message


# ===========================================================================
# Issue #18: Headers — conditional stripping
# ===========================================================================

class TestHeaderConditionalStripping:
    """_extract_header_value should strip if/unless conditionals."""

    def test_x_frame_options_with_conditional_pass(self):
        config = parse_string("""
frontend ft_web
    bind :443 ssl crt /cert.pem
    http-response set-header X-Frame-Options SAMEORIGIN if !is_stats
""")
        finding = check_x_frame_options(config)
        assert finding.status == Status.PASS

    def test_x_content_type_with_unless_pass(self):
        config = parse_string("""
frontend ft_web
    bind :443 ssl crt /cert.pem
    http-response set-header X-Content-Type-Options nosniff unless is_download
""")
        finding = check_x_content_type_options(config)
        assert finding.status == Status.PASS
