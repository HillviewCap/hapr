"""Tests for check improvements: cipher detection, mode filtering,
socket paths, password strength, SSL verify, redirect ports, log format."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
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
            "HAPR-HDR-009",
            "HAPR-TLS-006",
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


# ---------------------------------------------------------------------------
# New check tests: 16 checks
# ---------------------------------------------------------------------------

from hapr.framework.checks import (
    process,
    tls,
    global_defaults,
    headers,
    request,
    disclosure,
    frontend,
    backend,
    logging_checks as logging_checks_mod,
    timeouts,
    access,
)
from hapr.framework.checks.tls import check_ocsp_stapling, check_fips_ciphers, check_mtls_client_verification, check_client_crl_configured
from hapr.framework.checks.tls_live import check_certificate_key_size, check_certificate_expiry_warning, check_certificate_hostname_match
from hapr.framework.checks.frontend import check_spoe_waf_filter, check_spoe_agent_timeout, check_compression_breach_risk, check_proxy_protocol_restricted
from hapr.framework.checks.headers import check_cross_origin_resource_policy
from hapr.framework.checks.global_defaults import check_lua_memory_limit, check_lua_forced_yield, check_peer_encryption
from hapr.framework.checks.backend import check_cache_security
from hapr.framework.checks.request import check_h2_stream_limits, check_h2c_smuggling_prevention
from hapr.framework.checks.access import check_jwt_verification, check_jwt_algorithm_restriction, check_bot_detection, check_ip_reputation_integration, check_api_authentication, check_api_rate_limiting
from hapr.models import ScanResult, CertInfo


# ---------------------------------------------------------------------------
# HAPR-PROC-005: Daemon mode
# ---------------------------------------------------------------------------

class TestDaemonMode:
    """Test check_daemon_mode for HAPR-PROC-005."""

    def test_daemon_present_passes(self):
        config = parse_string("""
global
    daemon
    log /dev/log local0
""")
        finding = process.check_daemon_mode(config)
        assert finding.check_id == "HAPR-PROC-005"
        assert finding.status == Status.PASS

    def test_daemon_missing_fails(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = process.check_daemon_mode(config)
        assert finding.check_id == "HAPR-PROC-005"
        assert finding.status == Status.FAIL


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
# HAPR-GBL-006: hard-stop-after
# ---------------------------------------------------------------------------

class TestHardStopAfter:
    """Test check_hard_stop_after for HAPR-GBL-006."""

    def test_hard_stop_after_present_passes(self):
        config = parse_string("""
global
    hard-stop-after 30s
""")
        finding = global_defaults.check_hard_stop_after(config)
        assert finding.check_id == "HAPR-GBL-006"
        assert finding.status == Status.PASS

    def test_hard_stop_after_missing_fails(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = global_defaults.check_hard_stop_after(config)
        assert finding.check_id == "HAPR-GBL-006"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-GBL-007: nbproc not used
# ---------------------------------------------------------------------------

class TestNbprocNotUsed:
    """Test check_nbproc_not_used for HAPR-GBL-007."""

    def test_no_nbproc_with_nbthread_passes(self):
        config = parse_string("""
global
    nbthread 4
""")
        finding = global_defaults.check_nbproc_not_used(config)
        assert finding.check_id == "HAPR-GBL-007"
        assert finding.status == Status.PASS

    def test_no_nbproc_at_all_passes(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = global_defaults.check_nbproc_not_used(config)
        assert finding.check_id == "HAPR-GBL-007"
        assert finding.status == Status.PASS

    def test_nbproc_present_fails(self):
        config = parse_string("""
global
    nbproc 4
""")
        finding = global_defaults.check_nbproc_not_used(config)
        assert finding.check_id == "HAPR-GBL-007"
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
# HAPR-INF-005: XFF spoofing prevention
# ---------------------------------------------------------------------------

class TestXFFSpoofingPrevention:
    """Test check_xff_spoofing_prevention for HAPR-INF-005."""

    def test_del_header_with_forwardfor_passes(self):
        config = parse_string("""
defaults
    mode http
    option forwardfor
    http-request del-header X-Forwarded-For
""")
        finding = disclosure.check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.PASS

    def test_forwardfor_without_del_header_fails(self):
        config = parse_string("""
defaults
    mode http
    option forwardfor
""")
        finding = disclosure.check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.FAIL

    def test_no_forwardfor_returns_na(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = disclosure.check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-FRT-007: XFF configured
# ---------------------------------------------------------------------------

class TestXFFConfigured:
    """Test check_xff_configured for HAPR-FRT-007."""

    def test_forwardfor_in_defaults_passes(self):
        config = parse_string("""
defaults
    mode http
    option forwardfor
""")
        finding = frontend.check_xff_configured(config)
        assert finding.check_id == "HAPR-FRT-007"
        assert finding.status == Status.PASS

    def test_no_forwardfor_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = frontend.check_xff_configured(config)
        assert finding.check_id == "HAPR-FRT-007"
        assert finding.status == Status.FAIL

    def test_forwardfor_in_frontend_passes(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    option forwardfor
    default_backend bk_web
""")
        finding = frontend.check_xff_configured(config)
        assert finding.check_id == "HAPR-FRT-007"
        assert finding.status == Status.PASS


# ---------------------------------------------------------------------------
# HAPR-FRT-008: Bind address restrictions
# ---------------------------------------------------------------------------

class TestBindAddressRestrictions:
    """Test check_bind_address_restrictions for HAPR-FRT-008."""

    def test_specific_bind_address_passes(self):
        config = parse_string("""
frontend ft_web
    bind 10.0.0.1:443
    default_backend bk_web
""")
        finding = frontend.check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.PASS

    def test_wildcard_bind_address_fails(self):
        config = parse_string("""
frontend ft_web
    bind *:443
    default_backend bk_web
""")
        finding = frontend.check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.FAIL

    def test_no_bind_lines_returns_na(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = frontend.check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.NOT_APPLICABLE


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
        finding = backend.check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.PASS

    def test_ssl_verify_none_fails(self):
        config = parse_string("""
backend bk_api
    server web1 10.0.0.1:443 ssl verify none
""")
        finding = backend.check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.FAIL

    def test_no_ssl_returns_na(self):
        config = parse_string("""
backend bk_api
    server web1 10.0.0.1:80
""")
        finding = backend.check_backend_ssl_verification(config)
        assert finding.check_id == "HAPR-BKD-006"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-LOG-006: dontlognull
# ---------------------------------------------------------------------------

class TestDontlognull:
    """Test check_dontlognull for HAPR-LOG-006."""

    def test_dontlognull_in_defaults_passes(self):
        config = parse_string("""
defaults
    mode http
    option dontlognull
""")
        finding = logging_checks_mod.check_dontlognull(config)
        assert finding.check_id == "HAPR-LOG-006"
        assert finding.status == Status.PASS

    def test_no_dontlognull_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = logging_checks_mod.check_dontlognull(config)
        assert finding.check_id == "HAPR-LOG-006"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-LOG-007: Remote syslog
# ---------------------------------------------------------------------------

class TestRemoteSyslog:
    """Test check_remote_syslog for HAPR-LOG-007."""

    def test_remote_syslog_passes(self):
        config = parse_string("""
global
    log 10.0.0.5:514 local0
""")
        finding = logging_checks_mod.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.PASS

    def test_local_syslog_only_partial(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = logging_checks_mod.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.PARTIAL

    def test_no_log_directives_fails(self):
        config = parse_string("""
global
    daemon
""")
        finding = logging_checks_mod.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.FAIL


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
        finding = timeouts.check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.PASS

    def test_http_keep_alive_timeout_missing_fails(self):
        config = parse_string("""
defaults
    timeout client 30s
""")
        finding = timeouts.check_http_keepalive_timeout(config)
        assert finding.check_id == "HAPR-TMO-006"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-ACL-007: Source IP restrictions
# ---------------------------------------------------------------------------

class TestSourceIPRestrictions:
    """Test check_source_ip_restrictions for HAPR-ACL-007."""

    def test_src_acl_with_deny_passes(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl trusted_src src 10.0.0.0/8
    http-request deny if !trusted_src
    default_backend bk_web
""")
        finding = access.check_source_ip_restrictions(config)
        assert finding.check_id == "HAPR-ACL-007"
        assert finding.status == Status.PASS

    def test_no_src_acls_fails(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = access.check_source_ip_restrictions(config)
        assert finding.check_id == "HAPR-ACL-007"
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
# 8. HAPR-SPOE-001: SPOE WAF Filter
# ---------------------------------------------------------------------------

class TestSPOEWAFFilter:
    """Test check_spoe_waf_filter for HAPR-SPOE-001."""

    def test_pass_spoe_filter_present(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    default_backend bk_web
""")
        finding = check_spoe_waf_filter(config)
        assert finding.check_id == "HAPR-SPOE-001"
        assert finding.status == Status.PASS

    def test_fail_no_spoe_filter(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_spoe_waf_filter(config)
        assert finding.check_id == "HAPR-SPOE-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 9. HAPR-SPOE-002: SPOE Agent Timeout
# ---------------------------------------------------------------------------

class TestSPOEAgentTimeout:
    """Test check_spoe_agent_timeout for HAPR-SPOE-002."""

    def test_pass_spoe_with_timeout(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    timeout hello 100ms
    default_backend bk_web
""")
        finding = check_spoe_agent_timeout(config)
        assert finding.check_id == "HAPR-SPOE-002"
        assert finding.status == Status.PASS

    def test_fail_spoe_without_timeout(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    default_backend bk_web
""")
        finding = check_spoe_agent_timeout(config)
        assert finding.check_id == "HAPR-SPOE-002"
        assert finding.status == Status.FAIL

    def test_na_no_spoe_filter(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_spoe_agent_timeout(config)
        assert finding.check_id == "HAPR-SPOE-002"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 10. HAPR-COMP-001: Compression BREACH Risk
# ---------------------------------------------------------------------------

class TestCompressionBREACH:
    """Test check_compression_breach_risk for HAPR-COMP-001."""

    def test_pass_no_compression(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PASS

    def test_partial_ssl_with_compression(self):
        config = parse_string("frontend fe\n  bind :443 ssl crt /cert.pem\n  compression algo gzip")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PARTIAL


# ---------------------------------------------------------------------------
# 11. HAPR-PROXY-001: Proxy Protocol Restricted
# ---------------------------------------------------------------------------

class TestProxyProtocolRestricted:
    """Test check_proxy_protocol_restricted for HAPR-PROXY-001."""

    def test_pass_accept_proxy_with_src_acl(self):
        config = parse_string("""
frontend ft_web
    bind *:80 accept-proxy
    acl trusted_proxy src 10.0.0.0/8
    http-request deny if !trusted_proxy
    default_backend bk_web
""")
        finding = check_proxy_protocol_restricted(config)
        assert finding.check_id == "HAPR-PROXY-001"
        assert finding.status == Status.PASS

    def test_fail_accept_proxy_no_src_acl(self):
        config = parse_string("""
frontend ft_web
    bind *:80 accept-proxy
    default_backend bk_web
""")
        finding = check_proxy_protocol_restricted(config)
        assert finding.check_id == "HAPR-PROXY-001"
        assert finding.status == Status.FAIL

    def test_na_no_accept_proxy(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_proxy_protocol_restricted(config)
        assert finding.check_id == "HAPR-PROXY-001"
        assert finding.status == Status.NOT_APPLICABLE


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


# ---------------------------------------------------------------------------
# 13. HAPR-LUA-001: Lua Memory Limit
# ---------------------------------------------------------------------------

class TestLuaMemoryLimit:
    """Test check_lua_memory_limit for HAPR-LUA-001."""

    def test_pass_lua_with_maxmem(self):
        config = parse_string("""
global
    lua-load /etc/haproxy/lua/script.lua
    tune.lua.maxmem 64
""")
        finding = check_lua_memory_limit(config)
        assert finding.check_id == "HAPR-LUA-001"
        assert finding.status == Status.PASS

    def test_fail_lua_without_maxmem(self):
        config = parse_string("""
global
    lua-load /etc/haproxy/lua/script.lua
""")
        finding = check_lua_memory_limit(config)
        assert finding.check_id == "HAPR-LUA-001"
        assert finding.status == Status.FAIL

    def test_na_no_lua_load(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_lua_memory_limit(config)
        assert finding.check_id == "HAPR-LUA-001"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 14. HAPR-LUA-002: Lua Forced Yield
# ---------------------------------------------------------------------------

class TestLuaForcedYield:
    """Test check_lua_forced_yield for HAPR-LUA-002."""

    def test_pass_lua_with_forced_yield(self):
        config = parse_string("""
global
    lua-load /etc/haproxy/lua/script.lua
    tune.lua.forced-yield 10000
""")
        finding = check_lua_forced_yield(config)
        assert finding.check_id == "HAPR-LUA-002"
        assert finding.status == Status.PASS

    def test_fail_lua_without_forced_yield(self):
        config = parse_string("""
global
    lua-load /etc/haproxy/lua/script.lua
""")
        finding = check_lua_forced_yield(config)
        assert finding.check_id == "HAPR-LUA-002"
        assert finding.status == Status.FAIL

    def test_na_no_lua_load(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_lua_forced_yield(config)
        assert finding.check_id == "HAPR-LUA-002"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 15. HAPR-PEER-001: Peer Encryption
# ---------------------------------------------------------------------------

class TestPeerEncryption:
    """Test check_peer_encryption for HAPR-PEER-001."""

    def test_pass_peers_with_ssl(self):
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http

backend bk_web
    peers mypeers ssl crt /cert.pem
    server web1 10.0.0.1:80 check
""")
        finding = check_peer_encryption(config)
        assert finding.check_id == "HAPR-PEER-001"
        assert finding.status == Status.PASS

    def test_fail_peers_without_ssl(self):
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http

backend bk_web
    peers mypeers
    server web1 10.0.0.1:80 check
""")
        finding = check_peer_encryption(config)
        assert finding.check_id == "HAPR-PEER-001"
        assert finding.status == Status.FAIL

    def test_na_no_peers_config(self):
        config = parse_string("""
global
    log /dev/log local0

frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_peer_encryption(config)
        assert finding.check_id == "HAPR-PEER-001"
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
# 19. HAPR-JWT-001: JWT Verification
# ---------------------------------------------------------------------------

class TestJWTVerification:
    """Test check_jwt_verification for HAPR-JWT-001."""

    def test_pass_jwt_verify_present(self):
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    http-request set-var(txn.bearer) req.hdr(Authorization),word(2) jwt_verify(txn.bearer,/etc/haproxy/pubkey.pem)
    default_backend bk_api
""")
        finding = check_jwt_verification(config)
        assert finding.check_id == "HAPR-JWT-001"
        assert finding.status == Status.PASS

    def test_fail_jwt_referenced_no_verification(self):
        """JWT keyword present in config but no verification directive."""
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    http-request set-header X-JWT-Status ok
    default_backend bk_api
""")
        finding = check_jwt_verification(config)
        assert finding.check_id == "HAPR-JWT-001"
        assert finding.status == Status.FAIL

    def test_na_no_jwt_patterns(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_jwt_verification(config)
        assert finding.check_id == "HAPR-JWT-001"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 20. HAPR-JWT-002: JWT Algorithm Restriction
# ---------------------------------------------------------------------------

class TestJWTAlgorithmRestriction:
    """Test check_jwt_algorithm_restriction for HAPR-JWT-002."""

    def test_pass_jwt_with_rs256_algorithm(self):
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    http-request set-var(txn.bearer) req.hdr(Authorization),word(2) jwt_verify(txn.bearer,/key.pem,RS256)
    default_backend bk_api
""")
        finding = check_jwt_algorithm_restriction(config)
        assert finding.check_id == "HAPR-JWT-002"
        assert finding.status == Status.PASS

    def test_na_no_jwt_config(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_jwt_algorithm_restriction(config)
        assert finding.check_id == "HAPR-JWT-002"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 21. HAPR-BOT-001: Bot Detection
# ---------------------------------------------------------------------------

class TestBotDetection:
    """Test check_bot_detection for HAPR-BOT-001."""

    def test_pass_bot_acl_with_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl bad_bot hdr(User-Agent) -i bot
    http-request deny if bad_bot
    default_backend bk_web
""")
        finding = check_bot_detection(config)
        assert finding.check_id == "HAPR-BOT-001"
        assert finding.status == Status.PASS

    def test_fail_no_bot_detection(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_bot_detection(config)
        assert finding.check_id == "HAPR-BOT-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 22. HAPR-IPREP-001: IP Reputation Integration
# ---------------------------------------------------------------------------

class TestIPReputationIntegration:
    """Test check_ip_reputation_integration for HAPR-IPREP-001."""

    def test_pass_blocklist_with_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl blocklist src -f /etc/haproxy/blocklist.map
    http-request deny if blocklist
    default_backend bk_web
""")
        finding = check_ip_reputation_integration(config)
        assert finding.check_id == "HAPR-IPREP-001"
        assert finding.status == Status.PASS

    def test_fail_no_ip_reputation(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_ip_reputation_integration(config)
        assert finding.check_id == "HAPR-IPREP-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 23. HAPR-API-001: API Authentication
# ---------------------------------------------------------------------------

class TestAPIAuthentication:
    """Test check_api_authentication for HAPR-API-001."""

    def test_pass_api_path_with_auth(self):
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    acl is_api path_beg /api
    acl has_auth hdr(Authorization) -m found
    http-request deny if is_api !has_auth
    default_backend bk_api
""")
        finding = check_api_authentication(config)
        assert finding.check_id == "HAPR-API-001"
        assert finding.status == Status.PASS

    def test_na_no_api_paths(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_api_authentication(config)
        assert finding.check_id == "HAPR-API-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_fail_api_path_without_auth(self):
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    acl is_api path_beg /api
    use_backend bk_api if is_api
    default_backend bk_web
""")
        finding = check_api_authentication(config)
        assert finding.check_id == "HAPR-API-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# 24. HAPR-API-002: API Rate Limiting
# ---------------------------------------------------------------------------

class TestAPIRateLimiting:
    """Test check_api_rate_limiting for HAPR-API-002."""

    def test_pass_api_path_with_rate_limit(self):
        config = parse_string("""
frontend ft_api
    bind *:443 ssl crt /cert.pem
    acl is_api path_beg /api
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src if is_api
    http-request deny deny_status 429 if is_api { sc_http_req_rate(0) gt 100 }
    default_backend bk_api
""")
        finding = check_api_rate_limiting(config)
        assert finding.check_id == "HAPR-API-002"
        assert finding.status == Status.PASS

    def test_na_no_api_paths(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_api_rate_limiting(config)
        assert finding.check_id == "HAPR-API-002"
        assert finding.status == Status.NOT_APPLICABLE


# ===========================================================================
# TLS Category Validation Tests
# ===========================================================================

from hapr.framework.checks.tls import (
    check_min_tls_version,
    check_ssl_default_bind_options,
    check_ssl_default_bind_ciphers,
    check_ssl_default_bind_ciphersuites,
    check_dh_param_size,
)


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
# Logging Category Validation Tests
# ===========================================================================

from hapr.framework.checks.logging_checks import (
    check_logging_configured,
    check_log_format as check_log_format_fn,
    check_log_level,
    check_httplog_or_tcplog,
    check_dontlognull,
    check_remote_syslog,
)

from hapr.framework.checks.disclosure import (
    check_server_header_removed,
    check_custom_error_pages,
    check_version_hidden,
    check_stats_version_hidden,
    check_xff_spoofing_prevention,
)


class TestLogDirectivePresent:
    def test_pass_single(self):
        config = parse_string("global\n    log /dev/log local0\n")
        finding = check_logging_configured(config)
        assert finding.check_id == "HAPR-LOG-001" and finding.status == Status.PASS

    def test_pass_multiple(self):
        config = parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")
        finding = check_logging_configured(config)
        assert finding.check_id == "HAPR-LOG-001" and finding.status == Status.PASS

    def test_fail_no_log(self):
        config = parse_string("global\n    maxconn 4096\n")
        finding = check_logging_configured(config)
        assert finding.check_id == "HAPR-LOG-001" and finding.status == Status.FAIL

    def test_fail_empty(self):
        config = parse_string("global\n")
        finding = check_logging_configured(config)
        assert finding.check_id == "HAPR-LOG-001" and finding.status == Status.FAIL

    def test_pass_remote(self):
        config = parse_string("global\n    log 10.0.0.1:514 local0 info\n")
        finding = check_logging_configured(config)
        assert finding.check_id == "HAPR-LOG-001" and finding.status == Status.PASS


class TestLogFormatBackendCoverage:
    def test_pass_backend(self):
        config = parse_string("backend bk\n    log-format \"%ci:%cp\"\n    server s 10.0.0.1:80\n")
        finding = check_log_format_fn(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.PASS
        assert "backend" in finding.evidence.lower()

    def test_partial_httplog_backend(self):
        config = parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n")
        finding = check_log_format_fn(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.PARTIAL
        assert "backend" in finding.evidence.lower()

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        finding = check_log_format_fn(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.FAIL

    def test_pass_defaults(self):
        config = parse_string("defaults\n    log-format \"%ci:%cp\"\n")
        finding = check_log_format_fn(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.PASS


class TestLogLevelAllPaths:
    def test_fail_no_log(self):
        config = parse_string("global\n    maxconn 4096\n")
        assert check_log_level(config).status == Status.FAIL

    def test_pass_info(self):
        config = parse_string("global\n    log /dev/log local0 info\n")
        assert check_log_level(config).status == Status.PASS

    def test_pass_notice(self):
        config = parse_string("global\n    log /dev/log local0 notice\n")
        assert check_log_level(config).status == Status.PASS

    def test_pass_warning(self):
        config = parse_string("global\n    log /dev/log local0 warning\n")
        assert check_log_level(config).status == Status.PASS

    def test_partial_debug(self):
        config = parse_string("global\n    log /dev/log local0 debug\n")
        assert check_log_level(config).status == Status.PARTIAL

    def test_partial_err(self):
        config = parse_string("global\n    log /dev/log local0 err\n")
        assert check_log_level(config).status == Status.PARTIAL

    def test_partial_emerg(self):
        config = parse_string("global\n    log /dev/log local0 emerg\n")
        assert check_log_level(config).status == Status.PARTIAL

    def test_pass_no_level(self):
        config = parse_string("global\n    log /dev/log local0\n")
        assert check_log_level(config).status == Status.PASS


class TestHttplogTcplogBackendCoverage:
    def test_pass_httplog_backend(self):
        config = parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n")
        finding = check_httplog_or_tcplog(config)
        assert finding.status == Status.PASS and "backend" in finding.evidence.lower()

    def test_pass_tcplog_backend(self):
        config = parse_string("backend bk\n    option tcplog\n    server s 10.0.0.1:3306\n")
        finding = check_httplog_or_tcplog(config)
        assert finding.status == Status.PASS and "backend" in finding.evidence.lower()

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        assert check_httplog_or_tcplog(config).status == Status.FAIL

    def test_pass_defaults(self):
        config = parse_string("defaults\n    option httplog\n")
        assert check_httplog_or_tcplog(config).status == Status.PASS

    def test_pass_listen(self):
        config = parse_string("listen mysql\n    bind *:3306\n    option tcplog\n    server db 10.0.0.1:3306\n")
        assert check_httplog_or_tcplog(config).status == Status.PASS


class TestDontlognullBackendCoverage:
    def test_pass_backend(self):
        config = parse_string("backend bk\n    option dontlognull\n    server s 10.0.0.1:80\n")
        finding = check_dontlognull(config)
        assert finding.status == Status.PASS and "backend" in finding.evidence.lower()

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        assert check_dontlognull(config).status == Status.FAIL

    def test_pass_defaults(self):
        config = parse_string("defaults\n    option dontlognull\n")
        assert check_dontlognull(config).status == Status.PASS


class TestRemoteSyslogAdditionalPaths:
    def test_pass_remote(self):
        config = parse_string("global\n    log 10.0.0.1:514 local0\n")
        assert check_remote_syslog(config).status == Status.PASS

    def test_partial_local(self):
        config = parse_string("global\n    log /dev/log local0\n")
        assert check_remote_syslog(config).status == Status.PARTIAL

    def test_fail_none(self):
        config = parse_string("global\n    maxconn 4096\n")
        assert check_remote_syslog(config).status == Status.FAIL

    def test_pass_mixed(self):
        config = parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")
        assert check_remote_syslog(config).status == Status.PASS


class TestServerHeaderRemoved:
    def test_pass_del_frontend(self):
        config = parse_string("frontend ft\n    bind *:80\n    http-response del-header Server\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_pass_set_defaults(self):
        config = parse_string("defaults\n    http-response set-header Server MyProxy\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_pass_add_frontend(self):
        config = parse_string("frontend ft\n    bind *:80\n    http-response add-header Server Custom\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_pass_del_backend(self):
        config = parse_string("backend bk\n    http-response del-header Server\n    server s 10.0.0.1:80\n")
        f = check_server_header_removed(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

    def test_pass_rspidel(self):
        config = parse_string("defaults\n    rspidel ^Server\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_pass_rspdel(self):
        config = parse_string("defaults\n    rspdel ^Server\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_pass_listen(self):
        config = parse_string("listen app\n    bind *:80\n    http-response del-header Server\n    server s 10.0.0.1:80\n")
        assert check_server_header_removed(config).status == Status.PASS

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        assert check_server_header_removed(config).status == Status.FAIL

    def test_pass_add_backend(self):
        config = parse_string("backend bk\n    http-response add-header Server Custom\n    server s 10.0.0.1:80\n")
        f = check_server_header_removed(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()


class TestCustomErrorPages:
    def test_pass_many(self):
        config = parse_string("defaults\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")
        assert check_custom_error_pages(config).status == Status.PASS

    def test_partial_one(self):
        config = parse_string("defaults\n    errorfile 500 /e/500\n")
        assert check_custom_error_pages(config).status == Status.PARTIAL

    def test_partial_two(self):
        config = parse_string("defaults\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")
        assert check_custom_error_pages(config).status == Status.PARTIAL

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")
        assert check_custom_error_pages(config).status == Status.FAIL

    def test_pass_backend(self):
        config = parse_string("backend bk\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n")
        f = check_custom_error_pages(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

    def test_pass_frontend(self):
        config = parse_string("frontend ft\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n")
        assert check_custom_error_pages(config).status == Status.PASS

    def test_pass_listen(self):
        config = parse_string("listen app\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n")
        assert check_custom_error_pages(config).status == Status.PASS


class TestVersionInformationHidden:
    def test_pass_multi(self):
        config = parse_string("defaults\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")
        assert check_version_hidden(config).status == Status.PASS

    def test_partial_one(self):
        config = parse_string("defaults\n    http-response del-header X-Powered-By\n")
        assert check_version_hidden(config).status == Status.PARTIAL

    def test_partial_fwd(self):
        config = parse_string("defaults\n    option forwardfor header X-Real-IP\n")
        assert check_version_hidden(config).status == Status.PARTIAL

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")
        assert check_version_hidden(config).status == Status.FAIL

    def test_pass_backend(self):
        config = parse_string("backend bk\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n")
        f = check_version_hidden(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

    def test_pass_frontend(self):
        config = parse_string("frontend ft\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")
        assert check_version_hidden(config).status == Status.PASS

    def test_pass_listen(self):
        config = parse_string("listen app\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n")
        assert check_version_hidden(config).status == Status.PASS


class TestStatsVersionHidden:
    def test_pass_no_stats(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")
        assert check_stats_version_hidden(config).status == Status.PASS

    def test_pass_with_hide(self):
        config = parse_string("listen stats\n    bind *:8080\n    stats enable\n    stats hide-version\n")
        assert check_stats_version_hidden(config).status == Status.PASS

    def test_fail_no_hide(self):
        config = parse_string("listen stats\n    bind *:8080\n    stats enable\n")
        assert check_stats_version_hidden(config).status == Status.FAIL

    def test_fail_uri_no_hide(self):
        config = parse_string("frontend ft\n    bind *:8080\n    stats uri /admin\n")
        assert check_stats_version_hidden(config).status == Status.FAIL

    def test_pass_backend_hide(self):
        config = parse_string("backend bk\n    stats enable\n    stats hide-version\n    server s 10.0.0.1:80\n")
        f = check_stats_version_hidden(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

    def test_fail_backend_no_hide(self):
        config = parse_string("backend bk\n    stats enable\n    server s 10.0.0.1:80\n")
        assert check_stats_version_hidden(config).status == Status.FAIL

    def test_pass_defaults_hide(self):
        config = parse_string("defaults\n    stats enable\n    stats hide-version\n")
        assert check_stats_version_hidden(config).status == Status.PASS


class TestXFFSpoofingAdditionalPaths:
    def test_na_no_forwardfor(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")
        assert check_xff_spoofing_prevention(config).status == Status.NOT_APPLICABLE

    def test_pass_del_xff(self):
        config = parse_string("defaults\n    option forwardfor\n    http-request del-header X-Forwarded-For\n")
        assert check_xff_spoofing_prevention(config).status == Status.PASS

    def test_pass_set_xff(self):
        config = parse_string("defaults\n    option forwardfor\n    http-request set-header X-Forwarded-For %[src]\n")
        assert check_xff_spoofing_prevention(config).status == Status.PASS

    def test_partial_if_none(self):
        config = parse_string("defaults\n    option forwardfor if-none\n")
        assert check_xff_spoofing_prevention(config).status == Status.PARTIAL

    def test_fail_no_protect(self):
        config = parse_string("defaults\n    option forwardfor\n")
        assert check_xff_spoofing_prevention(config).status == Status.FAIL

    def test_pass_backend_xff(self):
        config = parse_string("backend bk\n    option forwardfor\n    http-request del-header X-Forwarded-For\n    server s 10.0.0.1:80\n")
        f = check_xff_spoofing_prevention(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()


from hapr.framework.checks.logging_checks import (
    check_logging_configured,
    check_log_format as check_log_format_fn,
    check_log_level,
    check_httplog_or_tcplog,
    check_dontlognull,
    check_remote_syslog,
)
from hapr.framework.checks.disclosure import (
    check_server_header_removed,
    check_custom_error_pages,
    check_version_hidden,
    check_stats_version_hidden,
    check_xff_spoofing_prevention,
)


class TestLogDirectivePresent:
    def test_pass_single(self):
        config = parse_string("global\n    log /dev/log local0\n")
        assert check_logging_configured(config).status == Status.PASS
    def test_pass_multiple(self):
        config = parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")
        assert check_logging_configured(config).status == Status.PASS
    def test_fail_no_log(self):
        config = parse_string("global\n    maxconn 4096\n")
        assert check_logging_configured(config).status == Status.FAIL
    def test_fail_empty(self):
        config = parse_string("global\n")
        assert check_logging_configured(config).status == Status.FAIL
    def test_pass_remote(self):
        config = parse_string("global\n    log 10.0.0.1:514 local0 info\n")
        assert check_logging_configured(config).status == Status.PASS

class TestLogFormatBackendCoverage:
    def test_pass_backend(self):
        config = parse_string("backend bk\n    log-format \"%ci\"\n    server s 10.0.0.1:80\n")
        f = check_log_format_fn(config)
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_partial_httplog_backend(self):
        config = parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n")
        f = check_log_format_fn(config)
        assert f.status == Status.PARTIAL and "backend" in f.evidence.lower()
    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        assert check_log_format_fn(config).status == Status.FAIL
    def test_pass_defaults(self):
        config = parse_string("defaults\n    log-format \"%ci\"\n")
        assert check_log_format_fn(config).status == Status.PASS

class TestLogLevelAllPaths:
    def test_fail_no_log(self):
        assert check_log_level(parse_string("global\n    maxconn 4096\n")).status == Status.FAIL
    def test_pass_info(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 info\n")).status == Status.PASS
    def test_pass_notice(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 notice\n")).status == Status.PASS
    def test_pass_warning(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 warning\n")).status == Status.PASS
    def test_partial_debug(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 debug\n")).status == Status.PARTIAL
    def test_partial_err(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 err\n")).status == Status.PARTIAL
    def test_partial_emerg(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 emerg\n")).status == Status.PARTIAL
    def test_pass_no_level(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0\n")).status == Status.PASS

class TestHttplogTcplogBackendCoverage:
    def test_pass_httplog_backend(self):
        f = check_httplog_or_tcplog(parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_tcplog_backend(self):
        f = check_httplog_or_tcplog(parse_string("backend bk\n    option tcplog\n    server s 10.0.0.1:3306\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_none(self):
        assert check_httplog_or_tcplog(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults(self):
        assert check_httplog_or_tcplog(parse_string("defaults\n    option httplog\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_httplog_or_tcplog(parse_string("listen m\n    bind *:3306\n    option tcplog\n    server d 10.0.0.1:3306\n")).status == Status.PASS

class TestDontlognullBackendCoverage:
    def test_pass_backend(self):
        f = check_dontlognull(parse_string("backend bk\n    option dontlognull\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_none(self):
        assert check_dontlognull(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults(self):
        assert check_dontlognull(parse_string("defaults\n    option dontlognull\n")).status == Status.PASS

class TestRemoteSyslogPaths:
    def test_pass_remote(self):
        assert check_remote_syslog(parse_string("global\n    log 10.0.0.1:514 local0\n")).status == Status.PASS
    def test_partial_local(self):
        assert check_remote_syslog(parse_string("global\n    log /dev/log local0\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_remote_syslog(parse_string("global\n    maxconn 4096\n")).status == Status.FAIL
    def test_pass_mixed(self):
        assert check_remote_syslog(parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")).status == Status.PASS

class TestServerHeaderRemoved:
    def test_pass_del_frontend(self):
        assert check_server_header_removed(parse_string("frontend ft\n    bind *:80\n    http-response del-header Server\n")).status == Status.PASS
    def test_pass_set_defaults(self):
        assert check_server_header_removed(parse_string("defaults\n    http-response set-header Server X\n")).status == Status.PASS
    def test_pass_add_frontend(self):
        assert check_server_header_removed(parse_string("frontend ft\n    bind *:80\n    http-response add-header Server X\n")).status == Status.PASS
    def test_pass_del_backend(self):
        f = check_server_header_removed(parse_string("backend bk\n    http-response del-header Server\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_rspidel(self):
        assert check_server_header_removed(parse_string("defaults\n    rspidel ^Server\n")).status == Status.PASS
    def test_pass_rspdel(self):
        assert check_server_header_removed(parse_string("defaults\n    rspdel ^Server\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_server_header_removed(parse_string("listen a\n    bind *:80\n    http-response del-header Server\n    server s 10.0.0.1:80\n")).status == Status.PASS
    def test_fail_none(self):
        assert check_server_header_removed(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_add_backend(self):
        f = check_server_header_removed(parse_string("backend bk\n    http-response add-header Server X\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

class TestCustomErrorPages:
    def test_pass_many(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")).status == Status.PASS
    def test_partial_one(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 500 /e/500\n")).status == Status.PARTIAL
    def test_partial_two(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_custom_error_pages(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_custom_error_pages(parse_string("backend bk\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_frontend(self):
        assert check_custom_error_pages(parse_string("frontend ft\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_custom_error_pages(parse_string("listen a\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n")).status == Status.PASS

class TestVersionInformationHidden:
    def test_pass_multi(self):
        assert check_version_hidden(parse_string("defaults\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")).status == Status.PASS
    def test_partial_one(self):
        assert check_version_hidden(parse_string("defaults\n    http-response del-header X-Powered-By\n")).status == Status.PARTIAL
    def test_partial_fwd(self):
        assert check_version_hidden(parse_string("defaults\n    option forwardfor header X-Real-IP\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_version_hidden(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_version_hidden(parse_string("backend bk\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_frontend(self):
        assert check_version_hidden(parse_string("frontend ft\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_version_hidden(parse_string("listen a\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n")).status == Status.PASS

class TestStatsVersionHidden:
    def test_pass_no_stats(self):
        assert check_stats_version_hidden(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.PASS
    def test_pass_hide(self):
        assert check_stats_version_hidden(parse_string("listen s\n    bind *:8080\n    stats enable\n    stats hide-version\n")).status == Status.PASS
    def test_fail_no_hide(self):
        assert check_stats_version_hidden(parse_string("listen s\n    bind *:8080\n    stats enable\n")).status == Status.FAIL
    def test_fail_uri_no_hide(self):
        assert check_stats_version_hidden(parse_string("frontend ft\n    bind *:8080\n    stats uri /admin\n")).status == Status.FAIL
    def test_pass_backend_hide(self):
        f = check_stats_version_hidden(parse_string("backend bk\n    stats enable\n    stats hide-version\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_backend_no_hide(self):
        assert check_stats_version_hidden(parse_string("backend bk\n    stats enable\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults_hide(self):
        assert check_stats_version_hidden(parse_string("defaults\n    stats enable\n    stats hide-version\n")).status == Status.PASS

class TestXFFSpoofingPaths:
    def test_na(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.NOT_APPLICABLE
    def test_pass_del(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n    http-request del-header X-Forwarded-For\n")).status == Status.PASS
    def test_pass_set(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n    http-request set-header X-Forwarded-For %[src]\n")).status == Status.PASS
    def test_partial_if_none(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor if-none\n")).status == Status.PARTIAL
    def test_fail(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_xff_spoofing_prevention(parse_string("backend bk\n    option forwardfor\n    http-request del-header X-Forwarded-For\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()


from hapr.framework.checks.logging_checks import (
    check_logging_configured,
    check_log_format as check_log_format_fn,
    check_log_level,
    check_httplog_or_tcplog,
    check_dontlognull,
    check_remote_syslog,
)
from hapr.framework.checks.disclosure import (
    check_server_header_removed,
    check_custom_error_pages,
    check_version_hidden,
    check_stats_version_hidden,
    check_xff_spoofing_prevention,
)


class TestLogDirectivePresent:
    def test_pass_single(self):
        config = parse_string("global\n    log /dev/log local0\n")
        assert check_logging_configured(config).status == Status.PASS
    def test_pass_multiple(self):
        config = parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")
        assert check_logging_configured(config).status == Status.PASS
    def test_fail_no_log(self):
        assert check_logging_configured(parse_string("global\n    maxconn 4096\n")).status == Status.FAIL
    def test_fail_empty(self):
        assert check_logging_configured(parse_string("global\n")).status == Status.FAIL
    def test_pass_remote(self):
        assert check_logging_configured(parse_string("global\n    log 10.0.0.1:514 local0 info\n")).status == Status.PASS

class TestLogFormatBackendCoverage:
    def test_pass_backend(self):
        f = check_log_format_fn(parse_string("backend bk\n    log-format \"%ci\"\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_partial_httplog_backend(self):
        f = check_log_format_fn(parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PARTIAL and "backend" in f.evidence.lower()
    def test_fail_none(self):
        assert check_log_format_fn(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults(self):
        assert check_log_format_fn(parse_string("defaults\n    log-format \"%ci\"\n")).status == Status.PASS

class TestLogLevelAllPaths:
    def test_fail_no_log(self):
        assert check_log_level(parse_string("global\n    maxconn 4096\n")).status == Status.FAIL
    def test_pass_info(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 info\n")).status == Status.PASS
    def test_pass_notice(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 notice\n")).status == Status.PASS
    def test_pass_warning(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 warning\n")).status == Status.PASS
    def test_partial_debug(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 debug\n")).status == Status.PARTIAL
    def test_partial_err(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 err\n")).status == Status.PARTIAL
    def test_partial_emerg(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0 emerg\n")).status == Status.PARTIAL
    def test_pass_no_level(self):
        assert check_log_level(parse_string("global\n    log /dev/log local0\n")).status == Status.PASS

class TestHttplogTcplogBackendCoverage:
    def test_pass_httplog_backend(self):
        f = check_httplog_or_tcplog(parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_tcplog_backend(self):
        f = check_httplog_or_tcplog(parse_string("backend bk\n    option tcplog\n    server s 10.0.0.1:3306\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_none(self):
        assert check_httplog_or_tcplog(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults(self):
        assert check_httplog_or_tcplog(parse_string("defaults\n    option httplog\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_httplog_or_tcplog(parse_string("listen m\n    bind *:3306\n    option tcplog\n    server d 10.0.0.1:3306\n")).status == Status.PASS

class TestDontlognullBackendCoverage:
    def test_pass_backend(self):
        f = check_dontlognull(parse_string("backend bk\n    option dontlognull\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_none(self):
        assert check_dontlognull(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults(self):
        assert check_dontlognull(parse_string("defaults\n    option dontlognull\n")).status == Status.PASS

class TestRemoteSyslogPaths:
    def test_pass_remote(self):
        assert check_remote_syslog(parse_string("global\n    log 10.0.0.1:514 local0\n")).status == Status.PASS
    def test_partial_local(self):
        assert check_remote_syslog(parse_string("global\n    log /dev/log local0\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_remote_syslog(parse_string("global\n    maxconn 4096\n")).status == Status.FAIL
    def test_pass_mixed(self):
        assert check_remote_syslog(parse_string("global\n    log /dev/log local0\n    log 10.0.0.1:514 local1\n")).status == Status.PASS

class TestServerHeaderRemoved:
    def test_pass_del_frontend(self):
        assert check_server_header_removed(parse_string("frontend ft\n    bind *:80\n    http-response del-header Server\n")).status == Status.PASS
    def test_pass_set_defaults(self):
        assert check_server_header_removed(parse_string("defaults\n    http-response set-header Server X\n")).status == Status.PASS
    def test_pass_add_frontend(self):
        assert check_server_header_removed(parse_string("frontend ft\n    bind *:80\n    http-response add-header Server X\n")).status == Status.PASS
    def test_pass_del_backend(self):
        f = check_server_header_removed(parse_string("backend bk\n    http-response del-header Server\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_rspidel(self):
        assert check_server_header_removed(parse_string("defaults\n    rspidel ^Server\n")).status == Status.PASS
    def test_pass_rspdel(self):
        assert check_server_header_removed(parse_string("defaults\n    rspdel ^Server\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_server_header_removed(parse_string("listen a\n    bind *:80\n    http-response del-header Server\n    server s 10.0.0.1:80\n")).status == Status.PASS
    def test_fail_none(self):
        assert check_server_header_removed(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_add_backend(self):
        f = check_server_header_removed(parse_string("backend bk\n    http-response add-header Server X\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()

class TestCustomErrorPages:
    def test_pass_many(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")).status == Status.PASS
    def test_partial_one(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 500 /e/500\n")).status == Status.PARTIAL
    def test_partial_two(self):
        assert check_custom_error_pages(parse_string("defaults\n    errorfile 500 /e/500\n    errorfile 502 /e/502\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_custom_error_pages(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_custom_error_pages(parse_string("backend bk\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_frontend(self):
        assert check_custom_error_pages(parse_string("frontend ft\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_custom_error_pages(parse_string("listen a\n    bind *:80\n    errorfile 400 /e/400\n    errorfile 403 /e/403\n    errorfile 500 /e/500\n    server s 10.0.0.1:80\n")).status == Status.PASS

class TestVersionInformationHidden:
    def test_pass_multi(self):
        assert check_version_hidden(parse_string("defaults\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")).status == Status.PASS
    def test_partial_one(self):
        assert check_version_hidden(parse_string("defaults\n    http-response del-header X-Powered-By\n")).status == Status.PARTIAL
    def test_partial_fwd(self):
        assert check_version_hidden(parse_string("defaults\n    option forwardfor header X-Real-IP\n")).status == Status.PARTIAL
    def test_fail_none(self):
        assert check_version_hidden(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_version_hidden(parse_string("backend bk\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_pass_frontend(self):
        assert check_version_hidden(parse_string("frontend ft\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n")).status == Status.PASS
    def test_pass_listen(self):
        assert check_version_hidden(parse_string("listen a\n    bind *:80\n    http-response del-header X-Powered-By\n    http-response del-header X-AspNet-Version\n    server s 10.0.0.1:80\n")).status == Status.PASS

class TestStatsVersionHidden:
    def test_pass_no_stats(self):
        assert check_stats_version_hidden(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.PASS
    def test_pass_hide(self):
        assert check_stats_version_hidden(parse_string("listen s\n    bind *:8080\n    stats enable\n    stats hide-version\n")).status == Status.PASS
    def test_fail_no_hide(self):
        assert check_stats_version_hidden(parse_string("listen s\n    bind *:8080\n    stats enable\n")).status == Status.FAIL
    def test_fail_uri_no_hide(self):
        assert check_stats_version_hidden(parse_string("frontend ft\n    bind *:8080\n    stats uri /admin\n")).status == Status.FAIL
    def test_pass_backend_hide(self):
        f = check_stats_version_hidden(parse_string("backend bk\n    stats enable\n    stats hide-version\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
    def test_fail_backend_no_hide(self):
        assert check_stats_version_hidden(parse_string("backend bk\n    stats enable\n    server s 10.0.0.1:80\n")).status == Status.FAIL
    def test_pass_defaults_hide(self):
        assert check_stats_version_hidden(parse_string("defaults\n    stats enable\n    stats hide-version\n")).status == Status.PASS

class TestXFFSpoofingPaths:
    def test_na(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\n")).status == Status.NOT_APPLICABLE
    def test_pass_del(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n    http-request del-header X-Forwarded-For\n")).status == Status.PASS
    def test_pass_set(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n    http-request set-header X-Forwarded-For %[src]\n")).status == Status.PASS
    def test_partial_if_none(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor if-none\n")).status == Status.PARTIAL
    def test_fail(self):
        assert check_xff_spoofing_prevention(parse_string("defaults\n    option forwardfor\n")).status == Status.FAIL
    def test_pass_backend(self):
        f = check_xff_spoofing_prevention(parse_string("backend bk\n    option forwardfor\n    http-request del-header X-Forwarded-For\n    server s 10.0.0.1:80\n"))
        assert f.status == Status.PASS and "backend" in f.evidence.lower()
