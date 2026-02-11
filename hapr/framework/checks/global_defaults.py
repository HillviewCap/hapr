"""Global & defaults section security checks."""

from __future__ import annotations

import os
import re

from ...models import Finding, HAProxyConfig, Status

# Directories considered world-writable / insecure for socket placement
_INSECURE_SOCKET_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

# Regex for IPv4 addresses (e.g. 192.168.1.1)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


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
            if any(socket_dir == d or socket_dir.startswith(d + "/") for d in _INSECURE_SOCKET_DIRS):
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


def _is_ip_address(address: str) -> bool:
    """Return True if *address* looks like an IPv4 or IPv6 literal."""
    if not address:
        return False
    # IPv6 addresses contain colons (e.g. ::1, fe80::1, [::1])
    if ":" in address:
        return True
    # IPv4 addresses are digits and dots (e.g. 192.168.1.1)
    return bool(_IPV4_RE.match(address))


def check_dns_resolver(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-003: Check if DNS resolvers are configured.

    DNS resolvers allow HAProxy to perform server name resolution dynamically.
    Only relevant when backend servers use hostnames rather than IP addresses.
    If all servers use static IPs, DNS resolution is not needed.
    """
    # First, determine if any server uses a hostname (not an IP address)
    hostname_servers: list[str] = []
    for server in config.all_servers:
        addr = server.address
        if addr and not _is_ip_address(addr):
            hostname_servers.append(f"{server.name} ({addr})")

    # If no servers use hostnames, DNS resolver is not needed
    if not hostname_servers:
        return Finding(
            check_id="HAPR-GBL-003",
            status=Status.NOT_APPLICABLE,
            message="All backend servers use static IP addresses; DNS resolver not required.",
            evidence="No server addresses requiring DNS resolution found.",
        )

    # Servers use hostnames — check if resolvers are configured
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
            message="DNS resolvers are configured for hostname-based servers.",
            evidence=f"Resolver references found; hostname servers: {', '.join(hostname_servers[:5])}",
        )
    else:
        return Finding(
            check_id="HAPR-GBL-003",
            status=Status.FAIL,
            message=(
                "Servers reference hostnames but no DNS resolvers are configured — "
                "server addresses are resolved only at startup."
            ),
            evidence=f"Hostname servers without resolvers: {', '.join(hostname_servers[:5])}",
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


# ---------------------------------------------------------------------------
# HAPR-GBL-006  hard-stop-after
# ---------------------------------------------------------------------------

def check_hard_stop_after(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-006: Check that ``hard-stop-after`` is set in the global section.

    The ``hard-stop-after`` directive sets a maximum time for graceful
    shutdown before HAProxy force-kills remaining connections.  Without it,
    HAProxy may hang indefinitely during reloads if long-lived connections
    do not close gracefully.

    Returns PASS if present, FAIL if missing.
    """
    if config.global_section.has("hard-stop-after"):
        value = config.global_section.get_value("hard-stop-after")
        return Finding(
            check_id="HAPR-GBL-006",
            status=Status.PASS,
            message=f"hard-stop-after is configured: {value}",
            evidence=f"hard-stop-after {value}",
        )

    return Finding(
        check_id="HAPR-GBL-006",
        status=Status.FAIL,
        message=(
            "No 'hard-stop-after' directive found in global section. "
            "Without it, HAProxy may hang during reloads if connections "
            "don't close gracefully."
        ),
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-GBL-007  nbproc not used (deprecated)
# ---------------------------------------------------------------------------

def check_nbproc_not_used(config: HAProxyConfig) -> Finding:
    """HAPR-GBL-007: Check that ``nbproc`` is NOT used in the global section.

    The ``nbproc`` directive is deprecated since HAProxy 2.5 and has been
    replaced by ``nbthread``.  Multi-process mode causes issues with
    shared state (stick-tables, peers, etc.) and should be migrated to
    multi-threading.

    Returns PASS if ``nbproc`` is absent, FAIL if present.
    """
    if config.global_section.has("nbproc"):
        value = config.global_section.get_value("nbproc")
        has_nbthread = config.global_section.has("nbthread")
        if has_nbthread:
            nbthread_value = config.global_section.get_value("nbthread")
            return Finding(
                check_id="HAPR-GBL-007",
                status=Status.FAIL,
                message=(
                    f"Deprecated 'nbproc {value}' is set alongside 'nbthread {nbthread_value}'. "
                    "Remove nbproc and rely solely on nbthread."
                ),
                evidence=f"nbproc {value}; nbthread {nbthread_value}",
            )
        return Finding(
            check_id="HAPR-GBL-007",
            status=Status.FAIL,
            message=(
                f"Deprecated 'nbproc {value}' is set in global section. "
                "Migrate to 'nbthread' for multi-threading support (HAProxy 2.5+)."
            ),
            evidence=f"nbproc {value}",
        )

    # nbproc not found — good
    has_nbthread = config.global_section.has("nbthread")
    if has_nbthread:
        nbthread_value = config.global_section.get_value("nbthread")
        return Finding(
            check_id="HAPR-GBL-007",
            status=Status.PASS,
            message=f"nbproc is not used; nbthread is configured ({nbthread_value}).",
            evidence=f"nbthread {nbthread_value}",
        )

    return Finding(
        check_id="HAPR-GBL-007",
        status=Status.PASS,
        message="nbproc is not used (deprecated directive absent).",
        evidence="nbproc not found",
    )


# NOTE: This function is no longer referenced in the baseline YAML (duplicate of tls.check_dh_param_size)
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
