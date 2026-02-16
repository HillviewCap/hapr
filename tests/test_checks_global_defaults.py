"""Tests for global/defaults check functions."""
from __future__ import annotations

from hapr.parser import parse_string
from hapr.models import Status
from hapr.framework.checks import global_defaults
from hapr.framework.checks.global_defaults import (
    check_stats_socket_permissions,
    check_secure_defaults,
    check_dns_resolver,
    check_global_maxconn,
    check_hard_stop_after,
    check_nbproc_not_used,
    check_lua_memory_limit,
    check_lua_forced_yield,
    check_peer_encryption,
)


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
# HAPR-GBL-001: Secure Defaults
# ---------------------------------------------------------------------------

class TestSecureDefaults:
    """Test check_secure_defaults for HAPR-GBL-001."""

    def test_pass_all_essential_directives(self):
        config = parse_string("""
defaults
    mode http
    log global
    timeout client 30s
    timeout server 30s
    timeout connect 5s
""")
        finding = check_secure_defaults(config)
        assert finding.check_id == "HAPR-GBL-001"
        assert finding.status == Status.PASS

    def test_fail_no_defaults_section(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_secure_defaults(config)
        assert finding.check_id == "HAPR-GBL-001"
        assert finding.status == Status.FAIL

    def test_partial_some_missing(self):
        config = parse_string("""
defaults
    mode http
    log global
    timeout client 30s
""")
        finding = check_secure_defaults(config)
        assert finding.check_id == "HAPR-GBL-001"
        assert finding.status == Status.PARTIAL

    def test_fail_most_missing(self):
        config = parse_string("""
defaults
    mode http
""")
        finding = check_secure_defaults(config)
        assert finding.check_id == "HAPR-GBL-001"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-GBL-002: Stats Socket Permissions - Extended
# ---------------------------------------------------------------------------

class TestStatsSocketPermissionsExtended:
    """Extended tests for check_stats_socket_permissions (HAPR-GBL-002)."""

    def test_not_applicable_no_socket(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.NOT_APPLICABLE

    def test_fail_missing_mode(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.FAIL

    def test_fail_mode_666_too_permissive(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock mode 666
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.FAIL
        assert "permissive" in finding.evidence.lower()

    def test_pass_mode_700_restrictive(self):
        """Mode 700 grants owner-only access and should PASS."""
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock mode 700
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.PASS

    def test_pass_mode_600(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock mode 600
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.PASS

    def test_fail_world_writable_dir(self):
        config = parse_string("""
global
    stats socket /dev/shm/haproxy.sock mode 660
""")
        finding = check_stats_socket_permissions(config)
        assert finding.check_id == "HAPR-GBL-002"
        assert finding.status == Status.FAIL
        assert "world-writable" in finding.evidence.lower()


# ---------------------------------------------------------------------------
# HAPR-GBL-003: DNS Resolver
# ---------------------------------------------------------------------------

class TestDNSResolver:
    """Test check_dns_resolver for HAPR-GBL-003."""

    def test_not_applicable_all_ip_servers(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check
    server web2 10.0.0.2:80 check
""")
        finding = check_dns_resolver(config)
        assert finding.check_id == "HAPR-GBL-003"
        assert finding.status == Status.NOT_APPLICABLE

    def test_fail_hostname_without_resolver(self):
        config = parse_string("""
backend bk_web
    server web1 web1.example.com:80 check
""")
        finding = check_dns_resolver(config)
        assert finding.check_id == "HAPR-GBL-003"
        assert finding.status == Status.FAIL

    def test_pass_hostname_with_resolver(self):
        config = parse_string("""
backend bk_web
    server web1 web1.example.com:80 check resolvers mydns
""")
        finding = check_dns_resolver(config)
        assert finding.check_id == "HAPR-GBL-003"
        assert finding.status == Status.PASS

    def test_not_applicable_no_servers(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_dns_resolver(config)
        assert finding.check_id == "HAPR-GBL-003"
        assert finding.status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# HAPR-GBL-004: Global Maxconn
# ---------------------------------------------------------------------------

class TestGlobalMaxconn:
    """Test check_global_maxconn for HAPR-GBL-004."""

    def test_pass_maxconn_set(self):
        config = parse_string("""
global
    maxconn 4096
""")
        finding = check_global_maxconn(config)
        assert finding.check_id == "HAPR-GBL-004"
        assert finding.status == Status.PASS

    def test_fail_maxconn_missing(self):
        config = parse_string("""
global
    log /dev/log local0
""")
        finding = check_global_maxconn(config)
        assert finding.check_id == "HAPR-GBL-004"
        assert finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# HAPR-GBL-007: nbproc not used - additional paths
# ---------------------------------------------------------------------------

class TestNbprocWithNbthread:
    """Test nbproc+nbthread combination for HAPR-GBL-007."""

    def test_fail_nbproc_with_nbthread(self):
        config = parse_string("""
global
    nbproc 4
    nbthread 2
""")
        finding = check_nbproc_not_used(config)
        assert finding.check_id == "HAPR-GBL-007"
        assert finding.status == Status.FAIL
        assert "nbproc" in finding.evidence
        assert "nbthread" in finding.evidence


# ---------------------------------------------------------------------------
# HAPR-LUA-001/002: Lua checks - lua-load-per-thread variant
# ---------------------------------------------------------------------------

class TestLuaLoadPerThread:
    """Test Lua checks trigger on lua-load-per-thread."""

    def test_lua_memory_limit_fail_per_thread(self):
        config = parse_string("""
global
    lua-load-per-thread /etc/haproxy/scripts/auth.lua
""")
        finding = check_lua_memory_limit(config)
        assert finding.check_id == "HAPR-LUA-001"
        assert finding.status == Status.FAIL

    def test_lua_forced_yield_fail_per_thread(self):
        config = parse_string("""
global
    lua-load-per-thread /etc/haproxy/scripts/auth.lua
""")
        finding = check_lua_forced_yield(config)
        assert finding.check_id == "HAPR-LUA-002"
        assert finding.status == Status.FAIL

    def test_lua_memory_limit_pass_per_thread(self):
        config = parse_string("""
global
    lua-load-per-thread /etc/haproxy/scripts/auth.lua
    tune.lua.maxmem 128
""")
        finding = check_lua_memory_limit(config)
        assert finding.check_id == "HAPR-LUA-001"
        assert finding.status == Status.PASS


# ===========================================================================
# Issue #31: Global — TCP stats socket should not require mode
# ===========================================================================

class TestStatsSocketTCP:
    """TCP-based stats sockets should not be flagged for missing mode."""

    def test_tcp_socket_no_mode_pass(self):
        config = parse_string("""
global
    stats socket 127.0.0.1:9999 level admin
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.PASS

    def test_unix_socket_no_mode_fail(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock level admin
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.FAIL
        assert "missing mode" in finding.evidence.lower()

    def test_unix_socket_with_mode_pass(self):
        config = parse_string("""
global
    stats socket /var/run/haproxy.sock mode 660 level admin
""")
        finding = check_stats_socket_permissions(config)
        assert finding.status == Status.PASS
