"""Global & defaults section security checks."""

from __future__ import annotations

import os

from ...models import Finding, HAProxyConfig, Status

# Directories considered world-writable / insecure for socket placement
_INSECURE_SOCKET_DIRS = {"/tmp", "/var/tmp", "/dev/shm"}


def check_secure_defaults(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-001: Check that a defaults section exists with essential directives.

    A defaults section should set mode, logging, timeouts, and common options
    so that frontends/backends inherit sane defaults.
    """
    if not config.defaults:
        return Finding(
            check_id="HAPR-GBL-001",
            status=Status.FAIL,
            message="No defaults section found in configuration",
            evidence="Missing 'defaults' section",
        )

    defaults = config.get_defaults()
    essential = ["mode", "log", "timeout client", "timeout server", "timeout connect"]
    found = []
    missing = []

    for kw in essential:
        # timeout directives are stored as "timeout" keyword with "client ..." args
        if kw.startswith("timeout "):
            sub = kw.split(" ", 1)[1]
            timeout_directives = defaults.get("timeout")
            if any(d.args.startswith(sub) for d in timeout_directives):
                found.append(kw)
            else:
                missing.append(kw)
        elif defaults.has(kw):
            found.append(kw)
        else:
            missing.append(kw)

    if not missing:
        return Finding(
            check_id="HAPR-GBL-001",
            status=Status.PASS,
            message="Defaults section contains all essential directives",
            evidence=f"Found: {', '.join(found)}",
        )
    elif len(found) >= 3:
        return Finding(
            check_id="HAPR-GBL-001",
            status=Status.PARTIAL,
            message=f"Defaults section missing some essential directives: {', '.join(missing)}",
            evidence=f"Found: {', '.join(found)}; Missing: {', '.join(missing)}",
        )
    else:
        return Finding(
            check_id="HAPR-GBL-001",
            status=Status.FAIL,
            message=f"Defaults section is missing most essential directives: {', '.join(missing)}",
            evidence=f"Found: {', '.join(found)}; Missing: {', '.join(missing)}",
        )


def check_stats_socket_permissions(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-002: Check stats socket has restrictive permissions.

    The stats socket should have mode set (e.g., mode 660) and ideally
    specify user/group restrictions.
    """
    stats_directives = config.global_section.get("stats")
    socket_directives = [d for d in stats_directives if d.args.startswith("socket")]

    if not socket_directives:
        return Finding(
            check_id="HAPR-GBL-002",
            status=Status.NOT_APPLICABLE,
            message="No stats socket configured",
            evidence="No 'stats socket' directive in global section",
        )

    issues = []
    for sd in socket_directives:
        args = sd.args
        # Validate socket path — args format: "socket /path/to/sock ..."
        # tokens[0] is "socket", tokens[1] is the actual path.
        tokens = args.split()
        if len(tokens) >= 2:
            socket_path = tokens[1]
            socket_dir = os.path.dirname(socket_path)
            if socket_dir in _INSECURE_SOCKET_DIRS:
                issues.append(
                    f"Stats socket in world-writable directory ({socket_dir}): {args}"
                )

        if "mode " not in args:
            issues.append(f"Stats socket missing mode restriction: {args}")
        elif "mode 600" not in args and "mode 660" not in args:
            # Check if mode is restrictive enough
            mode_start = args.index("mode ") + 5
            mode_val = args[mode_start:mode_start + 3].strip()
            if mode_val and int(mode_val) > 660:
                issues.append(f"Stats socket mode too permissive ({mode_val}): {args}")

        if "level " not in args and "admin" in args.lower():
            issues.append(f"Stats socket allows admin without level restriction: {args}")

    if not issues:
        return Finding(
            check_id="HAPR-GBL-002",
            status=Status.PASS,
            message="Stats socket has restrictive permissions",
            evidence=socket_directives[0].args,
        )
    else:
        return Finding(
            check_id="HAPR-GBL-002",
            status=Status.FAIL,
            message="Stats socket permissions are not restrictive enough",
            evidence="; ".join(issues),
        )


def check_dns_resolver(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-003: Check if DNS resolvers are configured.

    DNS resolvers allow HAProxy to perform server name resolution dynamically.
    """
    # Look for resolvers section references in server lines
    has_resolvers = False
    for server in config.all_servers:
        if "resolvers" in server.options:
            has_resolvers = True
            break

    # Also check for global dns/resolvers directives
    if not has_resolvers:
        for d in config.global_section.directives:
            if d.keyword in ("resolvers", "dns"):
                has_resolvers = True
                break

    if has_resolvers:
        return Finding(
            check_id="HAPR-GBL-003",
            status=Status.PASS,
            message="DNS resolvers are configured",
            evidence="Resolver references found in configuration",
        )
    else:
        return Finding(
            check_id="HAPR-GBL-003",
            status=Status.FAIL,
            message="No DNS resolvers configured — server addresses are resolved only at startup",
            evidence="No 'resolvers' directive found",
        )


def check_global_maxconn(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-004: Check that maxconn is set in the global section."""
    if config.global_section.has("maxconn"):
        value = config.global_section.get_value("maxconn")
        return Finding(
            check_id="HAPR-GBL-004",
            status=Status.PASS,
            message=f"Global maxconn is set to {value}",
            evidence=f"maxconn {value}",
        )
    else:
        return Finding(
            check_id="HAPR-GBL-004",
            status=Status.FAIL,
            message="No maxconn set in global section — HAProxy will use default",
            evidence="Missing 'maxconn' in global",
        )


def check_ssl_dh_param(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-005: Check tune.ssl.default-dh-param is set to >= 2048."""
    dh_directives = config.global_section.get("tune.ssl.default-dh-param")
    if not dh_directives:
        return Finding(
            check_id="HAPR-GBL-005",
            status=Status.FAIL,
            message="tune.ssl.default-dh-param is not set — default may be weak",
            evidence="Missing 'tune.ssl.default-dh-param' in global",
        )

    try:
        value = int(dh_directives[0].args.strip())
    except (ValueError, IndexError):
        return Finding(
            check_id="HAPR-GBL-005",
            status=Status.FAIL,
            message="tune.ssl.default-dh-param has invalid value",
            evidence=dh_directives[0].args,
        )

    if value >= 2048:
        return Finding(
            check_id="HAPR-GBL-005",
            status=Status.PASS,
            message=f"DH parameter size is {value} bits (>= 2048)",
            evidence=f"tune.ssl.default-dh-param {value}",
        )
    else:
        return Finding(
            check_id="HAPR-GBL-005",
            status=Status.FAIL,
            message=f"DH parameter size is only {value} bits — should be >= 2048",
            evidence=f"tune.ssl.default-dh-param {value}",
        )
