"""Tests for logging check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import logging_checks
from hapr.framework.checks.logging_checks import (
    check_logging_configured,
    check_log_format,
    check_log_level,
    check_httplog_or_tcplog,
    check_dontlognull,
    check_remote_syslog,
)


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
        finding = logging_checks.check_dontlognull(config)
        assert finding.check_id == "HAPR-LOG-006"
        assert finding.status == Status.PASS

    def test_no_dontlognull_fails(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = logging_checks.check_dontlognull(config)
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
        finding = logging_checks.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.PASS

    def test_local_syslog_only_partial(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = logging_checks.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.PARTIAL

    def test_no_log_directives_fails(self):
        config = parse_string("""
global
    daemon
""")
        finding = logging_checks.check_remote_syslog(config)
        assert finding.check_id == "HAPR-LOG-007"
        assert finding.status == Status.FAIL


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
        finding = check_log_format(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.PASS
        assert "backend" in finding.evidence.lower()

    def test_partial_httplog_backend(self):
        config = parse_string("backend bk\n    option httplog\n    server s 10.0.0.1:80\n")
        finding = check_log_format(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.PARTIAL
        assert "backend" in finding.evidence.lower()

    def test_fail_none(self):
        config = parse_string("defaults\n    mode http\nfrontend ft\n    bind *:80\nbackend bk\n    server s 10.0.0.1:80\n")
        finding = check_log_format(config)
        assert finding.check_id == "HAPR-LOG-002" and finding.status == Status.FAIL

    def test_pass_defaults(self):
        config = parse_string("defaults\n    log-format \"%ci:%cp\"\n")
        finding = check_log_format(config)
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


# ===========================================================================
# Issue #22 & #32: Logging — stdout and localhost as local targets
# ===========================================================================

class TestRemoteSyslogLocal:
    """check_remote_syslog should treat stdout, 127.0.0.1, and ::1 as local."""

    def test_stdout_is_local(self):
        config = parse_string("""
global
    log stdout format raw local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PARTIAL  # local only
        assert "local" in finding.evidence.lower()

    def test_stderr_is_local(self):
        config = parse_string("""
global
    log stderr format raw local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PARTIAL

    def test_fd_is_local(self):
        config = parse_string("""
global
    log fd@1 local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PARTIAL

    def test_127_0_0_1_is_local(self):
        config = parse_string("""
global
    log 127.0.0.1 local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PARTIAL

    def test_localhost_is_local(self):
        config = parse_string("""
global
    log localhost local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PARTIAL

    def test_remote_ip_is_remote(self):
        config = parse_string("""
global
    log 10.0.0.1:514 local0
""")
        finding = check_remote_syslog(config)
        assert finding.status == Status.PASS


# ===========================================================================
# Issue #23: Logging — custom log-format recognised
# ===========================================================================

class TestLogFormatRecognised:
    """check_httplog_or_tcplog should recognise custom log-format directives."""

    def test_log_format_pass(self):
        config = parse_string("""
defaults
    mode http
    log-format "%ci:%cp [%tr] %ft %b/%s %ST"
""")
        finding = check_httplog_or_tcplog(config)
        assert finding.status == Status.PASS
        assert "log-format" in finding.evidence.lower()

    def test_httplog_still_works(self):
        config = parse_string("""
defaults
    mode http
    option httplog
""")
        finding = check_httplog_or_tcplog(config)
        assert finding.status == Status.PASS

    def test_neither_fail(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_httplog_or_tcplog(config)
        assert finding.status == Status.FAIL
