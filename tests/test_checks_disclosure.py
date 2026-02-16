"""Tests for information disclosure check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks.disclosure import (
    check_server_header_removed,
    check_custom_error_pages,
    check_version_hidden,
    check_stats_version_hidden,
    check_xff_spoofing_prevention,
)
from hapr.framework.checks.headers import check_x_frame_options, check_x_content_type_options


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
        finding = check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.PASS

    def test_forwardfor_without_del_header_fails(self):
        config = parse_string("""
defaults
    mode http
    option forwardfor
""")
        finding = check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.FAIL

    def test_no_forwardfor_returns_na(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_xff_spoofing_prevention(config)
        assert finding.check_id == "HAPR-INF-005"
        assert finding.status == Status.NOT_APPLICABLE


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


# ===========================================================================
# Issue #19: Disclosure — regex del-header patterns
# ===========================================================================

class TestDelHeaderRegex:
    """del-header with regex patterns should be recognised."""

    def test_regex_server_header_pass(self):
        config = parse_string("""
frontend ft_web
    bind :80
    http-response del-header ^Server:.*
""")
        finding = check_server_header_removed(config)
        assert finding.status == Status.PASS

    def test_regex_version_header_pass(self):
        config = parse_string("""
defaults
    http-response del-header ^X-Powered-By:.*
    http-response del-header ^X-AspNet-Version:.*
""")
        finding = check_version_hidden(config)
        assert finding.status == Status.PASS
