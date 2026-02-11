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
