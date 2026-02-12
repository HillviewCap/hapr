"""HAProxy configuration parser.

Uses a line-by-line state machine to parse HAProxy config files into
structured ``HAProxyConfig`` model instances.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import (
    Backend,
    BindLine,
    DefaultsSection,
    Directive,
    Frontend,
    GlobalSection,
    HAProxyConfig,
    ListenSection,
    ServerLine,
    UserEntry,
    Userlist,
)

# Section header patterns
_SECTION_RE = re.compile(
    r"^(global|defaults|frontend|backend|listen|userlist)"
    r"(?:\s+(\S.*))?$"
)

# Bind line:  bind :443 ssl crt /etc/ssl/cert.pem
_BIND_RE = re.compile(
    r"^bind\s+(.+)$", re.IGNORECASE
)

# Server line:  server web1 10.0.0.1:80 check
_SERVER_RE = re.compile(
    r"^server\s+(\S+)\s+(\S+)(.*)$", re.IGNORECASE
)


def parse_file(path: str | Path) -> HAProxyConfig:
    """Parse a HAProxy configuration file and return a structured model."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    config = parse_string(text)
    config.file_path = str(path.resolve())
    return config


def parse_string(text: str) -> HAProxyConfig:
    """Parse HAProxy configuration text into a structured model."""
    config = HAProxyConfig()
    lines = text.splitlines()

    current_section: str | None = None
    current_name: str = ""
    current_obj: GlobalSection | DefaultsSection | Frontend | Backend | ListenSection | Userlist | None = None

    for line_num, raw_line in enumerate(lines, start=1):
        # Strip comments and whitespace
        line = _strip_comment(raw_line).strip()
        if not line:
            continue

        # Check for include directives
        if line.lower().startswith((".include", "include")):
            inc_path = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            config.warnings.append(
                f"Line {line_num}: include directive found ({inc_path}) — "
                "included files are not resolved by this parser"
            )
            continue

        # Check for section header
        m = _SECTION_RE.match(line)
        if m:
            # Save previous section
            _save_section(config, current_section, current_obj)

            current_section = m.group(1).lower()
            current_name = (m.group(2) or "").strip()

            if current_section == "global":
                current_obj = GlobalSection()
            elif current_section == "defaults":
                current_obj = DefaultsSection(name=current_name)
            elif current_section == "frontend":
                current_obj = Frontend(name=current_name)
            elif current_section == "backend":
                current_obj = Backend(name=current_name)
            elif current_section == "listen":
                current_obj = ListenSection(name=current_name)
            elif current_section == "userlist":
                current_obj = Userlist(name=current_name)
            continue

        if current_obj is None:
            continue

        # Parse directives within current section
        _parse_directive(current_obj, line, line_num)

    # Save last section
    _save_section(config, current_section, current_obj)

    return config


def _strip_comment(line: str) -> str:
    """Remove trailing comments (# style). Respects quoted strings."""
    in_quote = False
    quote_char = None
    for i, ch in enumerate(line):
        if ch in ('"', "'") and not in_quote:
            in_quote = True
            quote_char = ch
        elif ch == quote_char and in_quote:
            in_quote = False
            quote_char = None
        elif ch == "#" and not in_quote:
            return line[:i]
    return line


def _save_section(
    config: HAProxyConfig,
    section_type: str | None,
    obj: GlobalSection | DefaultsSection | Frontend | Backend | ListenSection | Userlist | None,
) -> None:
    """Append the completed section object to the config."""
    if obj is None or section_type is None:
        return
    if section_type == "global":
        config.global_section = obj  # type: ignore[assignment]
    elif section_type == "defaults":
        config.defaults.append(obj)  # type: ignore[arg-type]
    elif section_type == "frontend":
        config.frontends.append(obj)  # type: ignore[arg-type]
    elif section_type == "backend":
        config.backends.append(obj)  # type: ignore[arg-type]
    elif section_type == "listen":
        config.listens.append(obj)  # type: ignore[arg-type]
    elif section_type == "userlist":
        config.userlists.append(obj)  # type: ignore[arg-type]


def _parse_directive(
    section: GlobalSection | DefaultsSection | Frontend | Backend | ListenSection | Userlist,
    line: str,
    line_num: int,
) -> None:
    """Parse a single directive line and add it to the section."""
    # Bind line
    if isinstance(section, (Frontend, ListenSection)):
        bm = _BIND_RE.match(line)
        if bm:
            section.binds.append(_parse_bind(bm.group(1), line, line_num))
            return

    # Server line
    if isinstance(section, (Backend, ListenSection)):
        sm = _SERVER_RE.match(line)
        if sm:
            section.servers.append(
                _parse_server(sm.group(1), sm.group(2), sm.group(3), line, line_num)
            )
            return

    # Userlist directives
    if isinstance(section, Userlist):
        parts = line.split(None, 1)
        keyword = parts[0].lower()
        if keyword == "user" and len(parts) > 1:
            section.users.append(_parse_userlist_user(parts[1], line_num))
            return
        if keyword == "group" and len(parts) > 1:
            section.groups.append(Directive(keyword="group", args=parts[1], line_number=line_num))
            return

    # Generic directive
    parts = line.split(None, 1)
    keyword = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    section.directives.append(Directive(keyword=keyword, args=args, line_number=line_num))


def _parse_bind(args_str: str, raw: str, line_num: int) -> BindLine:
    """Parse bind directive arguments into a BindLine."""
    bind = BindLine(raw=raw, line_number=line_num)
    tokens = args_str.split()
    if not tokens:
        return bind

    # First token is address[:port] or :port or *:port
    addr_token = tokens[0]
    # Skip tokens that look like options (start with keyword patterns)
    if not addr_token.startswith(("ssl", "crt", "ca-", "alpn", "npn",
                                   "accept-proxy", "v4v6", "v6only",
                                   "transparent", "defer-accept", "name",
                                   "nice", "id", "process")):
        _parse_address(bind, addr_token)
        tokens = tokens[1:]

    # Parse remaining options
    options: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "ssl":
            bind.ssl = True
        elif tok in ("crt", "ca-file", "crl-file", "verify", "ciphers",
                      "ciphersuites", "alpn", "npn", "ssl-min-ver",
                      "ssl-max-ver", "curves", "ecdhe"):
            if i + 1 < len(tokens):
                options[tok] = tokens[i + 1]
                i += 1
        else:
            options[tok] = ""
        i += 1

    bind.options = options
    return bind


def _parse_address(bind: BindLine, addr_token: str) -> None:
    """Extract address and port from a bind address token."""
    # Handle formats: :443, *:443, 0.0.0.0:443, 127.0.0.1:443, [::]:443, /path/to/sock
    if addr_token.startswith("/"):
        bind.address = addr_token
        return

    if addr_token.startswith("["):
        # IPv6: [::]:443
        bracket_end = addr_token.find("]")
        if bracket_end != -1:
            bind.address = addr_token[1:bracket_end]
            rest = addr_token[bracket_end + 1:]
            if rest.startswith(":"):
                try:
                    bind.port = int(rest[1:])
                except ValueError:
                    pass
        return

    if ":" in addr_token:
        parts = addr_token.rsplit(":", 1)
        bind.address = parts[0] if parts[0] != "*" else "0.0.0.0"  # nosec B104 — parsing config, not binding
        try:
            bind.port = int(parts[1])
        except ValueError:
            bind.address = addr_token
    else:
        try:
            bind.port = int(addr_token)
        except ValueError:
            bind.address = addr_token


def _parse_server(
    name: str, address: str, rest: str, raw: str, line_num: int
) -> ServerLine:
    """Parse server directive into a ServerLine."""
    server = ServerLine(name=name, raw=raw, line_number=line_num)

    # Parse address:port
    if ":" in address and not address.startswith("["):
        parts = address.rsplit(":", 1)
        server.address = parts[0]
        try:
            server.port = int(parts[1])
        except ValueError:
            server.address = address
    elif address.startswith("["):
        bracket_end = address.find("]")
        if bracket_end != -1:
            server.address = address[1:bracket_end]
            port_part = address[bracket_end + 1:]
            if port_part.startswith(":"):
                try:
                    server.port = int(port_part[1:])
                except ValueError:
                    pass
    else:
        server.address = address

    # Parse options
    options: dict[str, str] = {}
    if rest:
        tokens = rest.split()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "ssl":
                server.ssl = True
            elif tok in ("check", "backup", "disabled", "agent-check",
                         "send-proxy", "send-proxy-v2"):
                options[tok] = ""
            elif tok in ("weight", "maxconn", "inter", "fastinter",
                         "downinter", "rise", "fall", "port", "addr",
                         "cookie", "id", "observe", "redir", "on-error",
                         "on-marked-down", "on-marked-up", "error-limit",
                         "slowstart", "ca-file", "crt", "verify",
                         "verifyhost", "sni", "ciphers", "ciphersuites",
                         "ssl-min-ver", "ssl-max-ver", "resolvers",
                         "resolve-prefer", "init-addr"):
                if i + 1 < len(tokens):
                    options[tok] = tokens[i + 1]
                    i += 1
            else:
                options[tok] = ""
            i += 1

    server.options = options
    return server


def _parse_userlist_user(args: str, line_num: int) -> UserEntry:
    """Parse a userlist ``user`` directive into a UserEntry.

    Format: ``user <name> [password|insecure-password] <value> [groups <g1>,<g2>]``
    """
    tokens = args.split()
    entry = UserEntry(line_number=line_num)

    if not tokens:
        return entry

    entry.name = tokens[0]
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("password", "insecure-password"):
            entry.password_type = tok
            if i + 1 < len(tokens):
                entry.password_value = tokens[i + 1]
                i += 1
        elif tok == "groups":
            if i + 1 < len(tokens):
                entry.groups = [g.strip() for g in tokens[i + 1].split(",")]
                i += 1
        i += 1

    return entry
