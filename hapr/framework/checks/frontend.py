"""Frontend security checks for HAProxy configurations.

Examines connection limits, HTTP-to-HTTPS redirection, WAF
integration, and application-layer attack protections (SQLi, XSS).
"""

from __future__ import annotations

import re

from ...models import HAProxyConfig, Finding, Status


def check_frontend_connection_limits(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-001: Check for connection rate limiting on frontends.

    Frontends should have ``rate-limit sessions`` or ``maxconn`` with a
    reasonable value to prevent a single source from exhausting
    connection capacity.

    Returns PASS if connection limits are found in frontends or listens,
    FAIL if not.
    """
    sections = config.all_frontends_and_listens
    if not sections:
        return Finding(
            check_id="HAPR-FRT-001",
            status=Status.NOT_APPLICABLE,
            message="No frontend or listen sections found.",
            evidence="Configuration contains no frontends or listens to evaluate.",
        )

    evidence_lines: list[str] = []

    for section in sections:
        section_label = section.name or "(unnamed)"

        # Check for rate-limit sessions
        for directive in section.directives:
            combined = f"{directive.keyword} {directive.args}".strip().lower()
            if combined.startswith("rate-limit sessions"):
                evidence_lines.append(
                    f"[{section_label}] rate-limit sessions {directive.args} "
                    f"(line {directive.line_number})"
                )

        # Check for maxconn directive
        if section.has("maxconn"):
            value = section.get_value("maxconn")
            evidence_lines.append(
                f"[{section_label}] maxconn {value}"
            )

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-001",
            status=Status.PASS,
            message="Frontend connection limits are configured.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-001",
        status=Status.FAIL,
        message=(
            "No connection rate limits found on frontends. "
            "Add 'rate-limit sessions' or 'maxconn' to frontend sections "
            "to prevent connection exhaustion."
        ),
        evidence="Searched all frontend and listen sections for rate-limit/maxconn; none found.",
    )


# NOTE: This function is no longer referenced in the baseline YAML (redundant with check_frontend_connection_limits + global_defaults.check_global_maxconn)
def check_maxconn_set(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-002: Check that maxconn is set in frontends or globally.

    Without a ``maxconn`` setting, HAProxy may accept unlimited
    connections and exhaust system resources.  It should be set in
    the global section or in individual frontends.

    Returns PASS if ``maxconn`` is found, FAIL if not.
    """
    evidence_lines: list[str] = []

    # Check global section
    if config.global_section.has("maxconn"):
        value = config.global_section.get_value("maxconn")
        evidence_lines.append(f"[global] maxconn {value}")

    # Check frontends
    for fe in config.frontends:
        fe_label = fe.name or "(unnamed)"
        if fe.has("maxconn"):
            value = fe.get_value("maxconn")
            evidence_lines.append(f"[{fe_label}] maxconn {value}")

    # Check listens
    for ls in config.listens:
        ls_label = ls.name or "(unnamed)"
        if ls.has("maxconn"):
            value = ls.get_value("maxconn")
            evidence_lines.append(f"[{ls_label}] maxconn {value}")

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-002",
            status=Status.PASS,
            message="maxconn is configured globally or in frontend sections.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-002",
        status=Status.FAIL,
        message=(
            "maxconn is not set in the global section or any frontend. "
            "Set 'maxconn' to limit the total number of concurrent connections "
            "and prevent resource exhaustion."
        ),
        evidence="Searched global, frontend, and listen sections for maxconn; not found.",
    )


_HTTP_PORTS = {80, 8080, 8000, 8888}


def check_http_to_https_redirect(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-003: Check for HTTP to HTTPS redirect on HTTP frontends.

    Frontends that bind on common HTTP ports (80, 8080, 8000, 8888)
    without SSL should redirect clients to HTTPS to ensure all traffic
    is encrypted.  This check looks for ``redirect scheme https`` or
    ``http-request redirect scheme https`` directives.

    Returns PASS if a redirect is found for all HTTP frontends, N/A
    if no frontends bind on HTTP ports, and FAIL if an HTTP frontend
    exists without a redirect.
    """
    http_sections: list[str] = []
    redirected_sections: list[str] = []
    non_redirected_sections: list[str] = []
    evidence_lines: list[str] = []

    for section in config.all_frontends_and_listens:
        section_label = section.name or "(unnamed)"

        # Determine if this section binds on a common HTTP port without SSL
        binds_http_port = False
        for bind in section.binds:
            if bind.port in _HTTP_PORTS and not bind.ssl:
                binds_http_port = True
                break

        if not binds_http_port:
            continue

        http_sections.append(section_label)

        # Look for redirect directives
        has_redirect = False
        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # 'redirect scheme https' as a standalone directive
            if keyword == "redirect" and "scheme https" in args_lower:
                has_redirect = True
                evidence_lines.append(
                    f"[{section_label}] redirect {directive.args} "
                    f"(line {directive.line_number})"
                )
                break

            # 'http-request redirect scheme https'
            if keyword == "http-request" and "redirect" in args_lower and "scheme https" in args_lower:
                has_redirect = True
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} "
                    f"(line {directive.line_number})"
                )
                break

        if has_redirect:
            redirected_sections.append(section_label)
        else:
            non_redirected_sections.append(section_label)

    if not http_sections:
        return Finding(
            check_id="HAPR-FRT-003",
            status=Status.NOT_APPLICABLE,
            message="No frontends bind on HTTP ports; HTTP-to-HTTPS redirect not applicable.",
            evidence="No non-SSL bind directives on HTTP ports (80, 8080, 8000, 8888) found.",
        )

    if non_redirected_sections:
        return Finding(
            check_id="HAPR-FRT-003",
            status=Status.FAIL,
            message=(
                "HTTP frontends found without HTTP-to-HTTPS redirect. "
                "Add 'redirect scheme https code 301' or "
                "'http-request redirect scheme https' to force encrypted connections."
            ),
            evidence=(
                f"HTTP sections without redirect: {', '.join(non_redirected_sections)}"
                + (f"\nRedirected: {', '.join(redirected_sections)}" if redirected_sections else "")
            ),
        )

    return Finding(
        check_id="HAPR-FRT-003",
        status=Status.PASS,
        message="All HTTP frontends redirect traffic to HTTPS.",
        evidence="\n".join(evidence_lines),
    )


def check_waf_integration(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-004: Check for Web Application Firewall (WAF) integration.

    Looks for indicators of WAF integration such as ``filter spoe``
    (ModSecurity via SPOE), ``spoe-message`` directives, references to
    modsecurity in configuration values, or HAProxy Enterprise WAF
    directives.

    Returns PASS if WAF indicators are detected, FAIL if not.  Note that
    many configurations will not include a WAF; this check is primarily
    informational.
    """
    waf_re = re.compile(
        r"modsecurity|filter\s+spoe|spoe-message|spoe-agent|waf",
        re.IGNORECASE,
    )
    evidence_lines: list[str] = []

    all_sections = (
        list(config.frontends)
        + list(config.backends)
        + list(config.listens)
    )

    for section in all_sections:
        section_label = section.name or "(unnamed)"

        for directive in section.directives:
            combined = f"{directive.keyword} {directive.args}"
            if waf_re.search(combined):
                evidence_lines.append(
                    f"[{section_label}] {directive.keyword} {directive.args} "
                    f"(line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-004",
            status=Status.PASS,
            message="WAF integration indicators detected in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-004",
        status=Status.FAIL,
        message=(
            "No WAF integration detected. Consider integrating a Web "
            "Application Firewall (e.g. ModSecurity via SPOE) for "
            "application-layer attack protection."
        ),
        evidence=(
            "Searched all sections for filter spoe, spoe-message, modsecurity, "
            "and WAF-related directives; none found."
        ),
    )


def check_sql_injection_protection(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-005: Check for SQL injection protection rules.

    Looks for ``http-request deny`` rules that match common SQL injection
    patterns (SELECT, UNION, INSERT, DROP, DELETE, UPDATE, ALTER, etc.)
    in URL or query parameters.  These rules provide a basic layer of
    defence against SQL injection attacks at the load-balancer level.

    Returns PASS if SQL injection deny rules are found, FAIL if not.
    """
    sqli_re = re.compile(
        r"(select|union|insert|drop|delete|update|alter|exec|execute|xp_)",
        re.IGNORECASE,
    )
    evidence_lines: list[str] = []

    for section in config.all_frontends_and_listens:
        section_label = section.name or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # Look for http-request deny rules with SQL patterns
            if keyword == "http-request" and "deny" in args_lower:
                if sqli_re.search(directive.args):
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} "
                        f"(line {directive.line_number})"
                    )

            # Also check ACLs that reference SQL patterns (used with deny)
            if keyword == "acl" and sqli_re.search(directive.args):
                # Verify there is a corresponding deny rule using this ACL
                acl_name_match = re.match(r"(\S+)", directive.args)
                if acl_name_match:
                    acl_name = acl_name_match.group(1)
                    for other in section.directives:
                        if (
                            other.keyword.lower() == "http-request"
                            and "deny" in other.args.lower()
                            and acl_name in other.args
                        ):
                            evidence_lines.append(
                                f"[{section_label}] acl {directive.args} "
                                f"(line {directive.line_number}) "
                                f"with deny rule at line {other.line_number}"
                            )
                            break

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-005",
            status=Status.PASS,
            message="SQL injection protection rules detected in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-005",
        status=Status.FAIL,
        message=(
            "No SQL injection protection rules found. Consider adding "
            "'http-request deny' rules that match common SQL injection "
            "patterns (SELECT, UNION, DROP, etc.) in URL and query parameters."
        ),
        evidence=(
            "Searched all frontend and listen sections for http-request deny "
            "rules with SQL injection patterns; none found."
        ),
    )


def check_xss_protection(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-006: Check for XSS (Cross-Site Scripting) protection rules.

    Looks for ``http-request deny`` rules that match common XSS patterns
    such as ``<script``, ``javascript:``, ``onerror=``, ``onload=``,
    ``eval(``, etc. in request parameters.  These rules add a basic
    defence layer against reflected XSS at the load-balancer level.

    Returns PASS if XSS deny rules are found, FAIL if not.
    """
    xss_re = re.compile(
        r"(<script|javascript:|onerror|onload|onclick|onfocus|onmouseover|eval\(|alert\(|document\.|\.cookie)",
        re.IGNORECASE,
    )
    evidence_lines: list[str] = []

    for section in config.all_frontends_and_listens:
        section_label = section.name or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # Look for http-request deny rules with XSS patterns
            if keyword == "http-request" and "deny" in args_lower:
                if xss_re.search(directive.args):
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} "
                        f"(line {directive.line_number})"
                    )

            # Also check ACLs that reference XSS patterns (used with deny)
            if keyword == "acl" and xss_re.search(directive.args):
                acl_name_match = re.match(r"(\S+)", directive.args)
                if acl_name_match:
                    acl_name = acl_name_match.group(1)
                    for other in section.directives:
                        if (
                            other.keyword.lower() == "http-request"
                            and "deny" in other.args.lower()
                            and acl_name in other.args
                        ):
                            evidence_lines.append(
                                f"[{section_label}] acl {directive.args} "
                                f"(line {directive.line_number}) "
                                f"with deny rule at line {other.line_number}"
                            )
                            break

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-006",
            status=Status.PASS,
            message="XSS protection rules detected in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-006",
        status=Status.FAIL,
        message=(
            "No XSS protection rules found. Consider adding "
            "'http-request deny' rules that match common XSS patterns "
            "(<script, javascript:, onerror=, etc.) in request parameters."
        ),
        evidence=(
            "Searched all frontend and listen sections for http-request deny "
            "rules with XSS patterns; none found."
        ),
    )


def check_xff_configured(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-007: Check that option forwardfor is configured.

    The ``option forwardfor`` directive instructs HAProxy to add or append
    the client IP address to the ``X-Forwarded-For`` header.  Without it,
    backend servers cannot determine the real client IP when HAProxy is
    acting as a reverse proxy.

    Returns PASS if ``option forwardfor`` is found in at least one
    frontend, listen, or defaults section.  FAIL otherwise.
    """
    evidence_lines: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.defaults)
    )

    for section in all_sections:
        section_name = getattr(section, "name", "unnamed") or "unnamed"
        for directive in section.get("option"):
            if "forwardfor" in directive.args.lower():
                evidence_lines.append(
                    f"[{section_name}] option {directive.args} "
                    f"(line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-FRT-007",
            status=Status.PASS,
            message="option forwardfor is configured to pass real client IP to backends.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-FRT-007",
        status=Status.FAIL,
        message=(
            "option forwardfor is not configured. Backend servers will not "
            "receive the real client IP address. Add 'option forwardfor' to "
            "frontend or defaults sections."
        ),
        evidence=(
            "Searched all frontend, listen, and defaults sections for "
            "option forwardfor; not found."
        ),
    )


# Wildcard bind addresses that indicate binding to all interfaces.
_WILDCARD_ADDRESSES = {"", "*", "0.0.0.0", "::", "::0"}


def check_bind_address_restrictions(config: HAProxyConfig) -> Finding:
    """HAPR-FRT-008: Check that frontend bind addresses are not wildcard.

    Binding to ``0.0.0.0``, ``*``, or ``::`` exposes the service on all
    network interfaces, which may include internal management networks.
    Using specific bind addresses limits the attack surface.

    Returns PASS if all binds use specific addresses, PARTIAL if some
    binds use specific addresses but others are wildcard, FAIL if all
    binds use wildcard addresses, N/A if no bind lines exist.
    """
    all_binds = config.all_binds

    if not all_binds:
        return Finding(
            check_id="HAPR-FRT-008",
            status=Status.NOT_APPLICABLE,
            message="No bind lines found in frontends or listen sections.",
            evidence="Configuration contains no bind directives to evaluate.",
        )

    specific_binds: list[str] = []
    wildcard_binds: list[str] = []

    for bind in all_binds:
        label = f"{bind.address or '*'}:{bind.port or '?'} (line {bind.line_number})"
        if bind.address.strip() in _WILDCARD_ADDRESSES:
            wildcard_binds.append(label)
        else:
            specific_binds.append(label)

    if not wildcard_binds:
        return Finding(
            check_id="HAPR-FRT-008",
            status=Status.PASS,
            message="All bind addresses use specific addresses (no wildcards).",
            evidence=f"Specific binds: {', '.join(specific_binds)}",
        )

    if specific_binds:
        return Finding(
            check_id="HAPR-FRT-008",
            status=Status.PARTIAL,
            message=(
                "Some bind addresses use specific addresses but others use "
                "wildcards. Consider restricting all binds to specific addresses."
            ),
            evidence=(
                f"Specific binds: {', '.join(specific_binds)}; "
                f"Wildcard binds: {', '.join(wildcard_binds)}"
            ),
        )

    return Finding(
        check_id="HAPR-FRT-008",
        status=Status.FAIL,
        message=(
            "All bind addresses use wildcards (0.0.0.0, *, or ::), exposing "
            "the service on all network interfaces. Bind to specific addresses "
            "to limit the attack surface."
        ),
        evidence=f"Wildcard binds: {', '.join(wildcard_binds)}",
    )
