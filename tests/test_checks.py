"""Tests for check improvements: cipher detection, mode filtering,
socket paths, password strength, SSL verify, redirect ports, log format."""

from __future__ import annotations

import pytest
from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks.tls import _find_weak_ciphers, check_no_weak_ciphers
from hapr.framework.checks.global_defaults import check_stats_socket_permissions
from hapr.framework.checks.access import check_stats_access_restricted
from hapr.framework.checks.backend import check_backend_ssl
from hapr.framework.checks.frontend import check_http_to_https_redirect
from hapr.framework.checks.logging_checks import check_log_format
from hapr.framework.checks import request, logging_checks, access
from hapr.framework.engine import run_audit, _config_has_http_mode


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


# ---------------------------------------------------------------------------
# Fix 2: Mode-aware check filtering (TCP vs HTTP)
# ---------------------------------------------------------------------------

class TestModeAwareFiltering:
    """Test that HTTP-only checks get N/A for TCP-only configs."""

    def test_tcp_only_config_skips_http_checks(self):
        config = parse_string("""
defaults
    mode tcp
    timeout client 30s
    timeout server 30s
    timeout connect 5s

frontend ft_tcp
    bind *:3306
    default_backend bk_mysql

backend bk_mysql
    server db1 10.0.0.1:3306 check
""")
        result = run_audit(config)
        # HTTP-only checks should return N/A
        http_check_ids = {
            "HAPR-HDR-001", "HAPR-HDR-002", "HAPR-HDR-003",
            "HAPR-HDR-004", "HAPR-HDR-005", "HAPR-HDR-006",
            "HAPR-REQ-001", "HAPR-REQ-002", "HAPR-REQ-003", "HAPR-REQ-004",
            "HAPR-ACL-002",
            "HAPR-FRT-003", "HAPR-FRT-004", "HAPR-FRT-005", "HAPR-FRT-006",
            "HAPR-INF-001", "HAPR-INF-003",
        }
        for finding in result.findings:
            if finding.check_id in http_check_ids:
                assert finding.status == Status.NOT_APPLICABLE, (
                    f"{finding.check_id} should be N/A for TCP-only config, got {finding.status}"
                )

    def test_http_config_runs_http_checks(self):
        config = parse_string("""
defaults
    mode http
    timeout client 30s
    timeout server 30s
    timeout connect 5s

frontend ft_web
    bind *:80
    default_backend bk_web

backend bk_web
    server web1 10.0.0.1:80 check
""")
        result = run_audit(config)
        # HTTP checks should NOT be N/A (they may pass or fail)
        for finding in result.findings:
            if finding.check_id == "HAPR-HDR-001":
                assert finding.status != Status.NOT_APPLICABLE

    def test_config_has_http_mode_explicit_http(self):
        config = parse_string("""
defaults
    mode http
""")
        assert _config_has_http_mode(config) is True

    def test_config_has_http_mode_explicit_tcp(self):
        config = parse_string("""
defaults
    mode tcp

frontend ft_tcp
    bind *:3306
    mode tcp
""")
        assert _config_has_http_mode(config) is False

    def test_config_has_http_mode_no_explicit_mode(self):
        """HAProxy defaults to HTTP when no mode is specified."""
        config = parse_string("""
defaults
    timeout client 30s
""")
        assert _config_has_http_mode(config) is True


# ---------------------------------------------------------------------------
# Fix 3: Stats socket path validation
# ---------------------------------------------------------------------------

class TestStatsSocketPath:
    """Test socket path validation in check_stats_socket_permissions."""

    def test_socket_in_tmp_flagged(self):
        config = parse_string("""
global
    stats socket /tmp/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.FAIL
        assert "/tmp" in finding.evidence

    def test_socket_in_var_run_passes(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.PASS

    def test_socket_in_var_tmp_flagged(self):
        config = parse_string("""
global
    stats socket /var/tmp/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.FAIL
        assert "/var/tmp" in finding.evidence


# ---------------------------------------------------------------------------
# Fix 4: Stats password strength check
# ---------------------------------------------------------------------------

class TestStatsPasswordStrength:
    """Test password strength validation for stats auth."""

    def test_weak_short_password(self):
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth admin:abc
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PARTIAL
        assert "too short" in finding.evidence

    def test_common_weak_password(self):
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth admin:password
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PARTIAL
        assert "common weak password" in finding.evidence

    def test_username_equals_password(self):
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth myuser01:myuser01
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PARTIAL
        assert "username equals password" in finding.evidence

    def test_strong_password_without_hardening_returns_partial(self):
        """Auth with strong password but missing hide-version and admin ACL returns PARTIAL."""
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth admin:Str0ng!P@ssw0rd#2024
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PARTIAL
        assert "stats hide-version" in finding.evidence

    def test_strong_password_with_full_hardening_passes(self):
        """Auth with strong password + hide-version + admin ACL returns PASS."""
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth admin:Str0ng!P@ssw0rd#2024
    stats hide-version
    stats admin if LOCALHOST
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PASS


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
# Fix 6: HTTP-to-HTTPS redirect port expansion
# ---------------------------------------------------------------------------

class TestHTTPRedirectPorts:
    """Test expanded port check for HTTP-to-HTTPS redirect."""

    def test_port_8080_without_redirect_fails(self):
        config = parse_string("""
frontend ft_alt
    bind *:8080
    default_backend bk_web
""")
        finding = check_http_to_https_redirect(config)
        assert finding.status == Status.FAIL

    def test_port_8080_with_redirect_passes(self):
        config = parse_string("""
frontend ft_alt
    bind *:8080
    redirect scheme https code 301
""")
        finding = check_http_to_https_redirect(config)
        assert finding.status == Status.PASS

    def test_port_443_ssl_not_flagged(self):
        """SSL frontends should not be checked for redirect."""
        config = parse_string("""
frontend ft_secure
    bind *:443 ssl crt /etc/ssl/cert.pem
    default_backend bk_web
""")
        finding = check_http_to_https_redirect(config)
        assert finding.status == Status.NOT_APPLICABLE

    def test_port_80_still_checked(self):
        config = parse_string("""
frontend ft_http
    bind *:80
    default_backend bk_web
""")
        finding = check_http_to_https_redirect(config)
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# Fix 7: Log format PARTIAL for httplog-only
# ---------------------------------------------------------------------------

class TestLogFormatPartial:
    """Test that option httplog returns PARTIAL and custom log-format returns PASS."""

    def test_httplog_only_returns_partial(self):
        config = parse_string("""
defaults
    mode http
    option httplog
""")
        finding = check_log_format(config)
        assert finding.status == Status.PARTIAL

    def test_custom_log_format_returns_pass(self):
        config = parse_string("""
defaults
    mode http
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B"
""")
        finding = check_log_format(config)
        assert finding.status == Status.PASS

    def test_both_custom_and_httplog_returns_pass(self):
        config = parse_string("""
defaults
    mode http
    option httplog
    log-format "%ci:%cp [%tr] %ft %b/%s %ST %B"
""")
        finding = check_log_format(config)
        assert finding.status == Status.PASS

    def test_no_log_format_returns_fail(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_log_format(config)
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-ACL-006: Userlist password check
# ---------------------------------------------------------------------------

from hapr.framework.checks.access import check_userlist_passwords


class TestUserlistPasswordCheck:
    """Test check_userlist_passwords for cleartext vs hashed detection."""

    def test_no_userlists_returns_na(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.NOT_APPLICABLE

    def test_insecure_password_returns_fail(self):
        config = parse_string("""
userlist myusers
    user admin insecure-password changeme
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.FAIL
        assert "insecure-password" in finding.evidence

    def test_hashed_password_returns_pass(self):
        config = parse_string("""
userlist myusers
    user admin password $5$salt$hashvalue
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.PASS

    def test_sha512_hash_passes(self):
        config = parse_string("""
userlist myusers
    user admin password $6$rounds=5000$saltsalt$longhashvaluehere
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.PASS

    def test_bcrypt_hash_passes(self):
        config = parse_string("""
userlist myusers
    user admin password $2b$12$saltsaltsaltsaltsaltsehashhashhashhashhashhashhash
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.PASS

    def test_unhashed_password_directive_fails(self):
        """password directive with plaintext (no crypt prefix) should fail."""
        config = parse_string("""
userlist myusers
    user admin password notahash
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.FAIL
        assert "crypt hash format" in finding.evidence

    def test_mixed_users_fails(self):
        """If any user is insecure, the whole check fails."""
        config = parse_string("""
userlist myusers
    user admin password $6$salt$hashvalue
    user guest insecure-password guest123
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.FAIL
        assert "guest" in finding.evidence

    def test_real_world_severalnines_pattern_fails(self):
        """Typical insecure userlist from real-world configs."""
        config = parse_string("""
userlist stats-auth
    group admin users admin
    user admin insecure-password admin
    group readonly users haproxy
    user haproxy insecure-password haproxy
""")
        finding = check_userlist_passwords(config)
        assert finding.status == Status.FAIL
        assert "admin" in finding.evidence
        assert "haproxy" in finding.evidence


# ---------------------------------------------------------------------------
# Socket prefix fix: /tmp/subdir should FAIL, /tmp.safe should PASS
# ---------------------------------------------------------------------------

class TestStatsSocketPathPrefix:
    """Test socket path prefix matching in check_stats_socket_permissions."""

    def test_socket_in_tmp_subdir_flagged(self):
        config = parse_string("""
global
    stats socket /tmp/subdir/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.FAIL
        assert "/tmp" in finding.evidence

    def test_socket_in_tmp_safe_passes(self):
        """Path /tmp.safe should NOT match /tmp."""
        config = parse_string("""
global
    stats socket /tmp.safe/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# Password priority fix: overlapping issues should all be reported
# ---------------------------------------------------------------------------

class TestStatsPasswordPriority:
    """Test that overlapping password issues are all reported."""

    def test_admin_admin_reports_both_short_and_common(self):
        config = parse_string("""
listen stats
    bind *:9000
    stats enable
    stats auth admin:admin
""")
        finding = check_stats_access_restricted(config)
        assert finding.status == Status.PARTIAL
        assert "too short" in finding.evidence
        assert "common weak" in finding.evidence


# ---------------------------------------------------------------------------
# Header value validation (Phase 2)
# ---------------------------------------------------------------------------

from hapr.framework.checks import headers
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
# Phase 2: ACL-001 per-frontend coverage
# ---------------------------------------------------------------------------

class TestACLPerFrontendCoverage:
    """Tests for Phase 2 ACL-001 per-frontend validation."""

    def test_all_frontends_have_acls_passes(self):
        config = parse_string("""
frontend web
    bind *:80
    acl is_admin path_beg /admin
    use_backend admin if is_admin
    default_backend app

frontend api
    bind *:8080
    acl is_health path /health
    default_backend app
""")
        finding = access.check_acls_defined(config)
        assert finding.status == Status.PASS

    def test_some_frontends_missing_acls_partial(self):
        config = parse_string("""
frontend web
    bind *:80
    acl is_admin path_beg /admin
    default_backend app

frontend api
    bind *:8080
    default_backend app
""")
        finding = access.check_acls_defined(config)
        assert finding.status == Status.PARTIAL

    def test_no_frontends_have_acls_fails(self):
        config = parse_string("""
frontend web
    bind *:80
    default_backend app
""")
        finding = access.check_acls_defined(config)
        assert finding.status == Status.FAIL


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
# Phase 2: LOG-004 emerg level restriction
# ---------------------------------------------------------------------------

class TestLogLevelEmergRestriction:
    """Tests for Phase 2 LOG-004 emerg level fix."""

    def test_emerg_level_returns_partial(self):
        config = parse_string("""
global
    log 127.0.0.1:514 local0 emerg
""")
        finding = logging_checks.check_log_level(config)
        assert finding.status == Status.PARTIAL

    def test_info_level_passes(self):
        config = parse_string("""
global
    log 127.0.0.1:514 local0 info
""")
        finding = logging_checks.check_log_level(config)
        assert finding.status == Status.PASS

    def test_crit_level_returns_partial(self):
        config = parse_string("""
global
    log 127.0.0.1:514 local0 crit
""")
        finding = logging_checks.check_log_level(config)
        assert finding.status == Status.PARTIAL
