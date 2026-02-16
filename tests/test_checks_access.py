"""Tests for access control check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import access
from hapr.framework.checks.access import (
    check_stats_access_restricted,
    check_userlist_passwords,
    check_acls_defined,
    check_source_ip_restrictions,
    check_jwt_verification,
    check_jwt_algorithm_restriction,
    check_bot_detection,
    check_ip_reputation_integration,
    check_api_authentication,
    check_api_rate_limiting,
)


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
# Issue #28: Access — GPC circuit breaker false positive
# ===========================================================================

class TestIPReputationGPCFalsePositive:
    """GPC counters for circuit breaking should not trigger IP reputation pass."""

    def test_gpc_circuit_breaker_not_ip_reputation(self):
        config = parse_string("""
frontend ft_web
    bind :80

backend bk_app
    stick-table type ip size 200k expire 5m store http_req_rate(10s),gpc0,gpc0_rate(10s),gpc1
    server web1 10.0.0.1:80 check
""")
        finding = check_ip_reputation_integration(config)
        assert finding.status == Status.FAIL  # Not IP reputation

    def test_gpc_with_src_deny_is_ip_reputation(self):
        config = parse_string("""
frontend ft_web
    bind :80
    stick-table type ip size 200k store gpc0
    http-request deny if { src_get_gpc0 gt 0 } { src -f /etc/haproxy/blacklist.lst }
""")
        finding = check_ip_reputation_integration(config)
        assert finding.status == Status.PASS
