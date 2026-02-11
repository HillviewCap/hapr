"""Backend security checks for HAProxy configurations.

Examines health checking, connection limits, backend SSL, cookie
security, and retry/redispatch settings.
"""

from __future__ import annotations

import re

from ...models import HAProxyConfig, Finding, Status


# Health-check option keywords recognised by HAProxy
_HEALTH_CHECK_OPTIONS = {
    "option httpchk",
    "option tcp-check",
    "option ldap-check",
    "option mysql-check",
    "option pgsql-check",
    "option redis-check",
    "option smtpchk",
}


def check_health_checks(config: HAProxyConfig) -> Finding:
    """HAPR-BKD-001: Check that backends have health checks configured.

    Backends should have a health-check option (``option httpchk``,
    ``option tcp-check``, ``option mysql-check``, etc.) or individual
    servers with the ``check`` keyword so that HAProxy can detect and
    remove unhealthy backends automatically.

    Returns PASS if all backends/listens have health checks, PARTIAL if
    some do, and FAIL if none do.
    """
    sections = config.all_backends_and_listens
    if not sections:
        return Finding(
            check_id="HAPR-BKD-001",
            status=Status.NOT_APPLICABLE,
            message="No backend or listen sections found.",
            evidence="Configuration contains no backends or listens to evaluate.",
        )

    with_checks: list[str] = []
    without_checks: list[str] = []

    for section in sections:
        section_label = section.name or "(unnamed)"

        # 1. Look for health-check option directives
        has_option = False
        for directive in section.directives:
            combined = f"{directive.keyword} {directive.args}".strip().lower()
            for opt in _HEALTH_CHECK_OPTIONS:
                if combined.startswith(opt):
                    has_option = True
                    break
            if has_option:
                break

        # 2. Look for servers with the 'check' option
        has_server_check = False
        servers = getattr(section, "servers", [])
        for server in servers:
            if "check" in server.options:
                has_server_check = True
                break

        if has_option or has_server_check:
            with_checks.append(section_label)
        else:
            without_checks.append(section_label)

    if not without_checks:
        return Finding(
            check_id="HAPR-BKD-001",
            status=Status.PASS,
            message="All backends/listens have health checks configured.",
            evidence=f"Sections with health checks: {', '.join(with_checks)}",
        )

    if with_checks:
        return Finding(
            check_id="HAPR-BKD-001",
            status=Status.PARTIAL,
            message="Some backends/listens are missing health checks.",
            evidence=(
                f"With health checks: {', '.join(with_checks)}; "
                f"Missing health checks: {', '.join(without_checks)}"
            ),
        )

    return Finding(
        check_id="HAPR-BKD-001",
        status=Status.FAIL,
        message=(
            "No health checks configured on any backend or listen section. "
            "Add 'option httpchk' or enable the 'check' keyword on server lines."
        ),
        evidence=f"Sections without health checks: {', '.join(without_checks)}",
    )


def check_connection_limits(config: HAProxyConfig) -> Finding:
    """HAPR-BKD-002: Check for connection limits on backends.

    Without ``maxconn`` on server lines or ``fullconn`` in backends,
    a sudden traffic spike can overwhelm backend servers.  This check
    verifies that at least some connection-limiting directives are in
    place.

    Returns PASS if connection limits are found, FAIL if none are found.
    """
    sections = config.all_backends_and_listens
    if not sections:
        return Finding(
            check_id="HAPR-BKD-002",
            status=Status.NOT_APPLICABLE,
            message="No backend or listen sections found.",
            evidence="Configuration contains no backends or listens to evaluate.",
        )

    evidence_lines: list[str] = []

    for section in sections:
        section_label = section.name or "(unnamed)"

        # Check for fullconn directive in the section
        if section.has("fullconn"):
            evidence_lines.append(f"[{section_label}] fullconn directive found")

        # Check for maxconn on individual server lines
        servers = getattr(section, "servers", [])
        for server in servers:
            if "maxconn" in server.options:
                evidence_lines.append(
                    f"[{section_label}] server {server.name} has maxconn={server.options['maxconn']}"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-BKD-002",
            status=Status.PASS,
            message="Backend connection limits are configured.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-BKD-002",
        status=Status.FAIL,
        message=(
            "No connection limits found on backend server lines or sections. "
            "Add 'maxconn' to server lines or 'fullconn' to backends to "
            "prevent backend overload."
        ),
        evidence="Searched all backend and listen sections for maxconn/fullconn; none found.",
    )


def check_backend_ssl(config: HAProxyConfig) -> Finding:
    """HAPR-BKD-003: Check that backend servers use SSL/TLS connections.

    Traffic between HAProxy and backend servers should be encrypted to
    prevent eavesdropping on internal networks.  This check looks for
    the ``ssl`` option on server lines.

    Returns PASS if all backend servers use SSL, PARTIAL if some do,
    FAIL if none do, and N/A if there are no backend servers.
    """
    all_servers = config.all_servers
    if not all_servers:
        return Finding(
            check_id="HAPR-BKD-003",
            status=Status.NOT_APPLICABLE,
            message="No backend servers defined in the configuration.",
            evidence="Configuration contains no server lines to evaluate.",
        )

    ssl_servers: list[str] = []
    non_ssl_servers: list[str] = []

    for server in all_servers:
        label = f"{server.name} ({server.address}:{server.port})"
        if server.ssl:
            ssl_servers.append(label)
        else:
            non_ssl_servers.append(label)

    if not non_ssl_servers:
        return Finding(
            check_id="HAPR-BKD-003",
            status=Status.PASS,
            message="All backend servers use SSL/TLS for connections.",
            evidence=f"SSL-enabled servers: {', '.join(ssl_servers)}",
        )

    if ssl_servers:
        return Finding(
            check_id="HAPR-BKD-003",
            status=Status.PARTIAL,
            message="Some backend servers are not using SSL/TLS connections.",
            evidence=(
                f"SSL-enabled: {', '.join(ssl_servers)}; "
                f"Without SSL: {', '.join(non_ssl_servers)}"
            ),
        )

    return Finding(
        check_id="HAPR-BKD-003",
        status=Status.FAIL,
        message=(
            "No backend servers use SSL/TLS. Traffic between HAProxy and "
            "backends is unencrypted. Add the 'ssl' option to server lines "
            "to encrypt backend connections."
        ),
        evidence=f"Servers without SSL: {', '.join(non_ssl_servers)}",
    )


def check_cookie_security(config: HAProxyConfig) -> Finding:
    """HAPR-BKD-004: Check cookie-based persistence security attributes.

    When cookie-based persistence is configured via the ``cookie``
    directive in backends, the cookie should include ``secure``,
    ``httponly``, and ``SameSite`` attributes to prevent theft via
    XSS or insecure transport.

    Returns PASS if cookies are secured, PARTIAL if the cookie exists
    but is missing some attributes, FAIL if the cookie has no security
    attributes, and N/A if no cookie persistence is configured.
    """
    sections = config.all_backends_and_listens
    sections_with_cookie: list[str] = []
    secured_sections: list[str] = []
    partial_sections: list[str] = []
    unsecured_sections: list[str] = []
    evidence_lines: list[str] = []

    for section in sections:
        section_label = section.name or "(unnamed)"
        cookie_directives = section.get("cookie")
        if not cookie_directives:
            continue

        for directive in cookie_directives:
            sections_with_cookie.append(section_label)
            args_lower = directive.args.lower()

            has_secure = "secure" in args_lower
            has_httponly = "httponly" in args_lower
            has_samesite = "samesite" in args_lower

            attrs_found = []
            attrs_missing = []

            for attr_name, attr_present in [
                ("secure", has_secure),
                ("httponly", has_httponly),
                ("SameSite", has_samesite),
            ]:
                if attr_present:
                    attrs_found.append(attr_name)
                else:
                    attrs_missing.append(attr_name)

            if attrs_missing and attrs_found:
                partial_sections.append(section_label)
                evidence_lines.append(
                    f"[{section_label}] cookie {directive.args} "
                    f"(missing: {', '.join(attrs_missing)})"
                )
            elif not attrs_found:
                unsecured_sections.append(section_label)
                evidence_lines.append(
                    f"[{section_label}] cookie {directive.args} "
                    f"(no security attributes)"
                )
            else:
                secured_sections.append(section_label)
                evidence_lines.append(
                    f"[{section_label}] cookie {directive.args} (fully secured)"
                )
            # Only process the first cookie directive per section
            break

    if not sections_with_cookie:
        return Finding(
            check_id="HAPR-BKD-004",
            status=Status.NOT_APPLICABLE,
            message="No cookie-based persistence configured.",
            evidence="No 'cookie' directives found in any backend or listen section.",
        )

    if unsecured_sections:
        return Finding(
            check_id="HAPR-BKD-004",
            status=Status.FAIL,
            message=(
                "Cookie-based persistence is configured without security attributes. "
                "Add 'secure', 'httponly', and 'SameSite' to cookie directives."
            ),
            evidence="\n".join(evidence_lines),
        )

    if partial_sections:
        return Finding(
            check_id="HAPR-BKD-004",
            status=Status.PARTIAL,
            message=(
                "Cookie-based persistence is configured but missing some security "
                "attributes. Ensure 'secure', 'httponly', and 'SameSite' are all set."
            ),
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-BKD-004",
        status=Status.PASS,
        message="Cookie-based persistence is properly secured with secure, httponly, and SameSite attributes.",
        evidence="\n".join(evidence_lines),
    )


def check_retry_redispatch(config: HAProxyConfig) -> Finding:
    """HAPR-BKD-005: Check for retry and redispatch configuration.

    ``option redispatch`` allows HAProxy to retry a request on a
    different server when the original fails.  The ``retries`` directive
    controls how many times a connection attempt is retried.  Both
    settings improve resilience.

    Returns PASS if both are found (in defaults or backends), PARTIAL
    if only one is present, and FAIL if neither is found.
    """
    has_retries = False
    has_redispatch = False
    evidence_lines: list[str] = []

    # Check defaults sections first
    for defaults in config.defaults:
        if defaults.has("retries"):
            has_retries = True
            value = defaults.get_value("retries")
            evidence_lines.append(f"[defaults] retries {value}")
        if defaults.has("option redispatch"):
            has_redispatch = True
            evidence_lines.append("[defaults] option redispatch")
        # Also check via directive scan for compound keywords
        for directive in defaults.directives:
            combined = f"{directive.keyword} {directive.args}".strip().lower()
            if combined.startswith("option redispatch"):
                has_redispatch = True
                if "[defaults] option redispatch" not in evidence_lines:
                    evidence_lines.append("[defaults] option redispatch")

    # Check backends and listens
    for section in config.all_backends_and_listens:
        section_label = section.name or "(unnamed)"
        if section.has("retries"):
            has_retries = True
            value = section.get_value("retries")
            evidence_lines.append(f"[{section_label}] retries {value}")
        if section.has("option redispatch"):
            has_redispatch = True
            evidence_lines.append(f"[{section_label}] option redispatch")
        for directive in section.directives:
            combined = f"{directive.keyword} {directive.args}".strip().lower()
            if combined.startswith("option redispatch"):
                has_redispatch = True
                line = f"[{section_label}] option redispatch"
                if line not in evidence_lines:
                    evidence_lines.append(line)

    if has_retries and has_redispatch:
        return Finding(
            check_id="HAPR-BKD-005",
            status=Status.PASS,
            message="Both 'retries' and 'option redispatch' are configured for backend resilience.",
            evidence="\n".join(evidence_lines),
        )

    if has_retries or has_redispatch:
        missing = "option redispatch" if not has_redispatch else "retries"
        return Finding(
            check_id="HAPR-BKD-005",
            status=Status.PARTIAL,
            message=(
                f"Only partial retry/redispatch configuration found. "
                f"Missing '{missing}'. Configure both 'retries' and "
                f"'option redispatch' for full backend resilience."
            ),
            evidence="\n".join(evidence_lines) if evidence_lines else f"Missing: {missing}",
        )

    return Finding(
        check_id="HAPR-BKD-005",
        status=Status.FAIL,
        message=(
            "Neither 'retries' nor 'option redispatch' is configured. "
            "Add both to defaults or backend sections to improve resilience "
            "when backend servers fail."
        ),
        evidence="Searched defaults and all backend/listen sections; neither directive found.",
    )
