"""Tests for the HAProxy configuration parser."""

import pytest
from hapr.parser import parse_string, parse_file
from hapr.models import HAProxyConfig


class TestParseString:
    """Test parse_string with various config snippets."""

    def test_empty_config(self):
        config = parse_string("")
        assert isinstance(config, HAProxyConfig)
        assert len(config.frontends) == 0
        assert len(config.backends) == 0

    def test_global_section(self):
        config = parse_string("""
global
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    maxconn 4096
""")
        assert config.global_section.has("log")
        assert config.global_section.has("chroot")
        assert config.global_section.has("user")
        assert config.global_section.has("group")
        assert config.global_section.get_value("maxconn") == "4096"
        assert config.global_section.get_value("user") == "haproxy"

    def test_defaults_section(self):
        config = parse_string("""
defaults
    mode http
    timeout client 30s
    timeout server 30s
    timeout connect 5s
    option httplog
""")
        assert len(config.defaults) == 1
        defaults = config.get_defaults()
        assert defaults.has("mode")
        assert defaults.get_value("mode") == "http"
        assert len(defaults.get("timeout")) == 3
        assert defaults.has("option")

    def test_frontend_with_bind(self):
        config = parse_string("""
frontend ft_https
    bind *:443 ssl crt /etc/ssl/cert.pem
    bind :80
    default_backend bk_web
""")
        assert len(config.frontends) == 1
        fe = config.frontends[0]
        assert fe.name == "ft_https"
        assert len(fe.binds) == 2

        ssl_bind = fe.binds[0]
        assert ssl_bind.port == 443
        assert ssl_bind.ssl is True
        assert "crt" in ssl_bind.options

        http_bind = fe.binds[1]
        assert http_bind.port == 80
        assert http_bind.ssl is False

    def test_backend_with_servers(self):
        config = parse_string("""
backend bk_web
    option httpchk GET /health
    server web1 10.0.0.1:8080 check
    server web2 10.0.0.2:8080 check ssl
""")
        assert len(config.backends) == 1
        be = config.backends[0]
        assert be.name == "bk_web"
        assert len(be.servers) == 2
        assert be.has("option")

        srv1 = be.servers[0]
        assert srv1.name == "web1"
        assert srv1.address == "10.0.0.1"
        assert srv1.port == 8080
        assert "check" in srv1.options
        assert srv1.ssl is False

        srv2 = be.servers[1]
        assert srv2.name == "web2"
        assert srv2.ssl is True

    def test_listen_section(self):
        config = parse_string("""
listen stats
    bind :9000
    stats enable
    stats uri /stats
    stats auth admin:password
    server local 127.0.0.1:8080
""")
        assert len(config.listens) == 1
        ls = config.listens[0]
        assert ls.name == "stats"
        assert len(ls.binds) == 1
        assert len(ls.servers) == 1
        assert ls.binds[0].port == 9000

    def test_multiple_sections(self):
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http

frontend ft_web
    bind :80
    default_backend bk_app

backend bk_app
    server app1 10.0.0.1:8080 check

listen stats
    bind :9000
    stats enable
""")
        assert config.global_section.has("log")
        assert len(config.defaults) == 1
        assert len(config.frontends) == 1
        assert len(config.backends) == 1
        assert len(config.listens) == 1

    def test_comments_stripped(self):
        config = parse_string("""
global
    # This is a comment
    log /dev/log local0  # inline comment
    maxconn 4096
""")
        assert config.global_section.has("log")
        assert config.global_section.has("maxconn")
        assert len(config.global_section.directives) == 2

    def test_include_warning(self):
        config = parse_string("""
global
    log /dev/log local0

.include /etc/haproxy/conf.d/*.cfg
""")
        assert len(config.warnings) == 1
        assert "include" in config.warnings[0].lower()

    def test_all_binds_property(self):
        config = parse_string("""
frontend ft1
    bind :80

frontend ft2
    bind :443 ssl crt /etc/ssl/cert.pem

listen ls1
    bind :9000
""")
        assert len(config.all_binds) == 3

    def test_all_servers_property(self):
        config = parse_string("""
backend bk1
    server s1 10.0.0.1:80
    server s2 10.0.0.2:80

listen ls1
    server s3 10.0.0.3:80
""")
        assert len(config.all_servers) == 3

    def test_bind_ipv6(self):
        config = parse_string("""
frontend ft1
    bind [::]:443 ssl crt /etc/ssl/cert.pem
""")
        bind = config.frontends[0].binds[0]
        assert bind.address == "::"
        assert bind.port == 443
        assert bind.ssl is True

    def test_frontend_acls(self):
        config = parse_string("""
frontend ft1
    bind :80
    acl is_admin path_beg /admin
    acl is_api path_beg /api
    use_backend bk_admin if is_admin
    default_backend bk_app
""")
        fe = config.frontends[0]
        assert len(fe.acls) == 2
        assert len(fe.use_backends) == 2

    def test_server_with_many_options(self):
        config = parse_string("""
backend bk1
    server s1 10.0.0.1:80 check inter 3s fall 3 rise 2 weight 100 maxconn 50
""")
        srv = config.backends[0].servers[0]
        assert "check" in srv.options
        assert srv.options.get("weight") == "100"
        assert srv.options.get("maxconn") == "50"
        assert srv.options.get("inter") == "3s"


class TestParseFile:
    """Test parse_file with actual config files."""

    def test_parse_secure_config(self):
        config = parse_file("examples/secure.cfg")
        assert len(config.frontends) >= 1
        assert len(config.backends) >= 1
        assert config.global_section.has("chroot")
        assert config.global_section.has("user")

    def test_parse_insecure_config(self):
        config = parse_file("examples/insecure.cfg")
        assert len(config.frontends) >= 1
        assert len(config.backends) >= 1

    def test_parse_mixed_config(self):
        config = parse_file("examples/mixed.cfg")
        assert len(config.frontends) >= 1
        assert len(config.backends) >= 1
        assert len(config.listens) >= 1

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_file("nonexistent.cfg")


class TestUserlistParsing:
    """Test parsing of HAProxy userlist sections."""

    def test_userlist_section_parsed(self):
        config = parse_string("""
userlist myusers
    user admin insecure-password changeme
""")
        assert len(config.userlists) == 1
        assert config.userlists[0].name == "myusers"
        assert len(config.userlists[0].users) == 1

    def test_insecure_password_extracted(self):
        config = parse_string("""
userlist myusers
    user admin insecure-password changeme
""")
        user = config.userlists[0].users[0]
        assert user.name == "admin"
        assert user.password_type == "insecure-password"
        assert user.password_value == "changeme"

    def test_hashed_password_extracted(self):
        config = parse_string("""
userlist myusers
    user admin password $6$rounds=5000$salt$hashvalue
""")
        user = config.userlists[0].users[0]
        assert user.name == "admin"
        assert user.password_type == "password"
        assert user.password_value.startswith("$6$")

    def test_user_with_groups(self):
        config = parse_string("""
userlist myusers
    user admin insecure-password changeme groups admins,operators
""")
        user = config.userlists[0].users[0]
        assert user.groups == ["admins", "operators"]

    def test_multiple_userlists(self):
        config = parse_string("""
userlist admins
    user admin password $5$salt$hashvalue

userlist operators
    user op1 insecure-password test123
    user op2 password $6$salt$hashvalue2
""")
        assert len(config.userlists) == 2
        assert config.userlists[0].name == "admins"
        assert len(config.userlists[0].users) == 1
        assert config.userlists[1].name == "operators"
        assert len(config.userlists[1].users) == 2

    def test_empty_userlist(self):
        config = parse_string("""
userlist empty_list
""")
        assert len(config.userlists) == 1
        assert config.userlists[0].name == "empty_list"
        assert len(config.userlists[0].users) == 0

    def test_userlist_between_other_sections(self):
        config = parse_string("""
frontend ft_web
    bind :80
    default_backend bk_web

userlist myusers
    user admin insecure-password changeme

backend bk_web
    server web1 10.0.0.1:8080 check
""")
        assert len(config.frontends) == 1
        assert len(config.userlists) == 1
        assert len(config.backends) == 1
        assert config.userlists[0].users[0].name == "admin"

    def test_userlist_group_directive(self):
        config = parse_string("""
userlist myusers
    group admins
    group operators
    user admin password $6$salt$hash groups admins
""")
        ul = config.userlists[0]
        assert len(ul.groups) == 2
        assert ul.groups[0].keyword == "group"
        assert ul.groups[0].args == "admins"

    def test_userlist_in_all_sections(self):
        config = parse_string("""
userlist myusers
    user admin password $6$salt$hash
""")
        assert any(
            hasattr(s, "users") for s in config.all_sections
        )




# ===========================================================================
# Issue #24: Parser — unrecognized sections (program, peers, resolvers) bleed
# ===========================================================================

class TestUnmodeledSectionBoundary:
    """Parser should treat program/peers/resolvers as section boundaries."""

    def test_peers_section_does_not_bleed_into_backend(self):
        config = parse_string("""
backend bk_web
    server web1 10.0.0.1:80 check

peers mypeers
    peer haproxy1 10.0.0.1:10000
    peer haproxy2 10.0.0.2:10000

frontend ft_web
    bind :80
""")
        # The peers directives should NOT appear in bk_web or ft_web
        be = config.backends[0]
        assert be.name == "bk_web"
        # Only the server line should be present, not peer directives
        assert len(be.servers) == 1
        assert len(config.frontends) == 1

    def test_resolvers_section_does_not_bleed(self):
        config = parse_string("""
global
    log /dev/log local0

resolvers mydns
    nameserver dns1 10.0.0.1:53
    resolve_retries 3

defaults
    mode http
""")
        # Resolvers directives should not end up in global
        g = config.global_section
        assert not g.has("nameserver")
        assert not g.has("resolve_retries")
        assert len(config.defaults) == 1

    def test_program_section_does_not_bleed(self):
        config = parse_string("""
global
    log /dev/log local0

program haproxy-api
    command /usr/bin/haproxy-api
    option start-on-reload

frontend ft_web
    bind :80
""")
        g = config.global_section
        assert not g.has("command")
        assert len(config.frontends) == 1




# ===========================================================================
# Issue #25: Parser — default-server inheritance
# ===========================================================================

class TestDefaultServerInheritance:
    """Parser should merge default-server options into server lines."""

    def test_check_option_inherited(self):
        config = parse_string("""
backend bk_app
    default-server ssl check maxconn 500
    server app1 10.0.0.1:443
    server app2 10.0.0.2:443
""")
        be = config.backends[0]
        assert len(be.servers) == 2
        for s in be.servers:
            assert "check" in s.options
            assert "maxconn" in s.options
            assert s.options["maxconn"] == "500"
            assert s.ssl is True

    def test_explicit_override_not_clobbered(self):
        config = parse_string("""
backend bk_app
    default-server maxconn 500 check
    server app1 10.0.0.1:443 maxconn 1000
""")
        s = config.backends[0].servers[0]
        assert s.options["maxconn"] == "1000"  # explicit overrides default

    def test_no_default_server_no_change(self):
        config = parse_string("""
backend bk_app
    server app1 10.0.0.1:443 check
""")
        s = config.backends[0].servers[0]
        assert "check" in s.options
        assert s.ssl is False




# ===========================================================================
# Issue #26: Parser — env var ports
# ===========================================================================

class TestEnvVarBindParsing:
    """Parser should preserve address even when port contains env vars."""

    def test_env_var_port_preserves_address(self):
        config = parse_string("""
frontend ft_http
    bind *:${HTTP_PORT}
""")
        b = config.frontends[0].binds[0]
        assert b.address == "0.0.0.0"
        assert b.port is None  # can't parse env var as int

    def test_env_var_port_with_explicit_address(self):
        config = parse_string("""
frontend ft_http
    bind 0.0.0.0:${STATS_PORT}
""")
        b = config.frontends[0].binds[0]
        assert b.address == "0.0.0.0"

