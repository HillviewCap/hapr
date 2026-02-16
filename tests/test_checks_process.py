"""Tests for process check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import process
from hapr.framework.checks.process import (
    check_non_root_user,
    check_user_group,
    check_daemon_mode,
)


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


# ===========================================================================
# Issue #27: Process — uid and master-worker
# ===========================================================================

class TestProcessUidAndMasterWorker:
    """check_non_root_user should recognise uid, check_daemon_mode should
    recognise master-worker."""

    def test_uid_non_root_pass(self):
        config = parse_string("global\n    uid 200\n")
        finding = check_non_root_user(config)
        assert finding.status == Status.PASS
        assert "uid 200" in finding.evidence

    def test_uid_root_fail(self):
        config = parse_string("global\n    uid 0\n")
        finding = check_non_root_user(config)
        assert finding.status == Status.FAIL

    def test_user_still_works(self):
        config = parse_string("global\n    user haproxy\n")
        finding = check_non_root_user(config)
        assert finding.status == Status.PASS

    def test_no_user_or_uid_fail(self):
        config = parse_string("global\n    log /dev/log local0\n")
        finding = check_non_root_user(config)
        assert finding.status == Status.FAIL

    def test_master_worker_pass(self):
        config = parse_string("global\n    master-worker\n")
        finding = check_daemon_mode(config)
        assert finding.status == Status.PASS
        assert "master-worker" in finding.evidence

    def test_daemon_still_works(self):
        config = parse_string("global\n    daemon\n")
        finding = check_daemon_mode(config)
        assert finding.status == Status.PASS

    def test_no_daemon_or_master_worker_fail(self):
        config = parse_string("global\n    log /dev/log local0\n")
        finding = check_daemon_mode(config)
        assert finding.status == Status.FAIL


# ===========================================================================
# Issue #30: Process — gid directive
# ===========================================================================

class TestProcessGid:
    """check_user_group should recognise gid directive."""

    def test_gid_pass(self):
        config = parse_string("global\n    gid 200\n")
        finding = check_user_group(config)
        assert finding.status == Status.PASS
        assert "gid 200" in finding.evidence

    def test_group_still_works(self):
        config = parse_string("global\n    group haproxy\n")
        finding = check_user_group(config)
        assert finding.status == Status.PASS

    def test_no_group_or_gid_fail(self):
        config = parse_string("global\n    log /dev/log local0\n")
        finding = check_user_group(config)
        assert finding.status == Status.FAIL
