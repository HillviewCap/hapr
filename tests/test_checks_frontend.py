"""Tests for frontend check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks.frontend import (
    check_http_to_https_redirect,
    check_xff_configured,
    check_bind_address_restrictions,
    check_spoe_waf_filter,
    check_spoe_agent_timeout,
    check_compression_breach_risk,
    check_proxy_protocol_restricted,
    check_frontend_connection_limits,
    check_waf_integration,
    check_sql_injection_protection,
    check_xss_protection,
)


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
        finding = check_xff_configured(config)
        assert finding.check_id == "HAPR-FRT-007"
        assert finding.status == Status.PASS

    def test_no_forwardfor_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_xff_configured(config)
        assert finding.check_id == "HAPR-FRT-007"
        assert finding.status == Status.FAIL

    def test_forwardfor_in_frontend_passes(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    option forwardfor
    default_backend bk_web
""")
        finding = check_xff_configured(config)
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
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.PASS

    def test_wildcard_bind_address_fails(self):
        config = parse_string("""
frontend ft_web
    bind *:443
    default_backend bk_web
""")
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.FAIL

    def test_no_bind_lines_returns_na(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
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


class TestFrontendConnectionLimits:
    """Test check_frontend_connection_limits for HAPR-FRT-001."""

    def test_pass_maxconn(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    maxconn 10000
""")
        finding = check_frontend_connection_limits(config)
        assert finding.check_id == "HAPR-FRT-001"
        assert finding.status == Status.PASS

    def test_pass_rate_limit(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    rate-limit sessions 100
""")
        finding = check_frontend_connection_limits(config)
        assert finding.check_id == "HAPR-FRT-001"
        assert finding.status == Status.PASS

    def test_fail_no_limits(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_frontend_connection_limits(config)
        assert finding.check_id == "HAPR-FRT-001"
        assert finding.status == Status.FAIL

    def test_na_no_frontends(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_frontend_connection_limits(config)
        assert finding.check_id == "HAPR-FRT-001"
        assert finding.status == Status.NOT_APPLICABLE

    def test_pass_listen_section(self):
        config = parse_string("""
listen my_app
    bind *:80
    maxconn 5000
    server web1 10.0.0.1:80 check
""")
        finding = check_frontend_connection_limits(config)
        assert finding.check_id == "HAPR-FRT-001"
        assert finding.status == Status.PASS


class TestWAFIntegrationAdditional:
    """Additional tests for check_waf_integration (HAPR-FRT-004)."""

    def test_pass_modsecurity(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
""")
        finding = check_waf_integration(config)
        assert finding.check_id == "HAPR-FRT-004"
        assert finding.status == Status.PASS

    def test_fail_no_waf(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_waf_integration(config)
        assert finding.check_id == "HAPR-FRT-004"
        assert finding.status == Status.FAIL

    def test_pass_waf_in_defaults(self):
        config = parse_string("""
defaults
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
""")
        finding = check_waf_integration(config)
        assert finding.check_id == "HAPR-FRT-004"
        assert finding.status == Status.PASS

    def test_pass_waf_in_backend(self):
        config = parse_string("""
backend bk_web
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    server web1 10.0.0.1:80 check
""")
        finding = check_waf_integration(config)
        assert finding.check_id == "HAPR-FRT-004"
        assert finding.status == Status.PASS


class TestSQLInjectionProtection:
    """Test check_sql_injection_protection for HAPR-FRT-005."""

    def test_pass_direct_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny if { url_sub -i select union insert drop }
""")
        finding = check_sql_injection_protection(config)
        assert finding.check_id == "HAPR-FRT-005"
        assert finding.status == Status.PASS

    def test_pass_acl_with_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl sqli_detect url_sub -i select union insert drop update delete
    http-request deny if sqli_detect
""")
        finding = check_sql_injection_protection(config)
        assert finding.check_id == "HAPR-FRT-005"
        assert finding.status == Status.PASS

    def test_fail_no_protection(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_sql_injection_protection(config)
        assert finding.check_id == "HAPR-FRT-005"
        assert finding.status == Status.FAIL

    def test_pass_listen_section(self):
        config = parse_string("""
listen my_app
    bind *:80
    http-request deny if { url_sub -i select union insert drop }
    server web1 10.0.0.1:80 check
""")
        finding = check_sql_injection_protection(config)
        assert finding.check_id == "HAPR-FRT-005"
        assert finding.status == Status.PASS


class TestXSSProtectionRules:
    """Test check_xss_protection for HAPR-FRT-006."""

    def test_pass_direct_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    http-request deny if { url_sub -i <script javascript: onerror onload }
""")
        finding = check_xss_protection(config)
        assert finding.check_id == "HAPR-FRT-006"
        assert finding.status == Status.PASS

    def test_pass_acl_with_deny(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    acl xss_detect url_sub -i <script javascript: onerror onload
    http-request deny if xss_detect
""")
        finding = check_xss_protection(config)
        assert finding.check_id == "HAPR-FRT-006"
        assert finding.status == Status.PASS

    def test_fail_no_protection(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    default_backend bk_web
""")
        finding = check_xss_protection(config)
        assert finding.check_id == "HAPR-FRT-006"
        assert finding.status == Status.FAIL

    def test_pass_listen_section(self):
        config = parse_string("""
listen my_app
    bind *:80
    http-request deny if { url_sub -i <script javascript: onerror }
    server web1 10.0.0.1:80 check
""")
        finding = check_xss_protection(config)
        assert finding.check_id == "HAPR-FRT-006"
        assert finding.status == Status.PASS


class TestBindAddressRestrictionsAdditional:
    """Additional tests for check_bind_address_restrictions (HAPR-FRT-008)."""

    def test_partial_mixed(self):
        config = parse_string("""
frontend ft_web
    bind 10.0.0.1:443 ssl crt /cert.pem

frontend ft_admin
    bind *:8080
""")
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.PARTIAL

    def test_fail_ipv6_wildcard(self):
        config = parse_string("""
frontend ft_web
    bind [::]:443 ssl crt /cert.pem
""")
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.FAIL

    def test_pass_ipv6_specific(self):
        config = parse_string("""
frontend ft_web
    bind [2001:db8::1]:443 ssl crt /cert.pem
""")
        finding = check_bind_address_restrictions(config)
        assert finding.check_id == "HAPR-FRT-008"
        assert finding.status == Status.PASS


class TestCompressionBREACHAdditional:
    """Additional tests for check_compression_breach_risk (HAPR-COMP-001)."""

    def test_pass_no_compression(self):
        config = parse_string("""
frontend ft_web
    bind *:443 ssl crt /cert.pem
    default_backend bk_web
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PASS

    def test_pass_compression_on_non_ssl(self):
        config = parse_string("""
frontend ft_web
    bind *:80
    compression algo gzip
    default_backend bk_web
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PASS

    def test_partial_compression_on_ssl(self):
        config = parse_string("""
frontend ft_web
    bind *:443 ssl crt /cert.pem
    compression algo gzip
    default_backend bk_web
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PARTIAL

    def test_partial_defaults_compression(self):
        config = parse_string("""
defaults
    compression algo gzip
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PARTIAL

    def test_partial_backend_compression(self):
        config = parse_string("""
backend bk_web
    compression algo gzip
    server web1 10.0.0.1:80 check
""")
        finding = check_compression_breach_risk(config)
        assert finding.check_id == "HAPR-COMP-001"
        assert finding.status == Status.PARTIAL


class TestProxyProtocolRestrictedAdditional:
    """Additional tests for check_proxy_protocol_restricted (HAPR-PROXY-001)."""

    def test_partial_non_src_acl(self):
        config = parse_string("""
frontend ft_web
    bind *:443 ssl crt /cert.pem accept-proxy
    acl is_health path /health
    http-request deny unless is_health
""")
        finding = check_proxy_protocol_restricted(config)
        assert finding.check_id == "HAPR-PROXY-001"
        assert finding.status == Status.PARTIAL
