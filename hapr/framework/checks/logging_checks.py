"""Logging and monitoring security checks for HAProxy configurations.

Checks cover log directive presence, log format detail, stats endpoint
security, log level appropriateness, and HTTP/TCP log options.
"""

from __future__ import annotations

from ...models import HAProxyConfig, Finding, Status


def check_logging_configured(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-001: Check that logging is configured in the global section.

    HAProxy requires a ``log`` directive in the global section to enable
    centralized logging.  Without it, no log messages are emitted by
    default, making incident investigation and monitoring impossible.

    Returns PASS if at least one ``log`` directive exists in the global
    section, FAIL otherwise.
    """
    log_directives = config.global_section.get("log")

    if log_directives:
        targets = [f"log {d.args}" for d in log_directives]
        return Finding(
            check_id="HAPR-LOG-001",
            status=Status.PASS,
            message="Logging is configured in the global section.",
            evidence=f"Found {len(log_directives)} log directive(s): " + "; ".join(targets),
        )

    return Finding(
        check_id="HAPR-LOG-001",
        status=Status.FAIL,
        message=(
            "No 'log' directive found in the global section. "
            "Add a log target (e.g. 'log /dev/log local0' or "
            "'log 127.0.0.1:514 local0') to enable logging."
        ),
        evidence="No log directives found in global section.",
    )


def check_log_format(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-002: Check for detailed log format configuration.

    The default HAProxy log format is minimal.  A custom ``log-format``
    directive provides the richest information including timers, status
    codes, and headers.  ``option httplog`` is better than the default but
    still limited compared to a custom format.

    This check searches defaults, frontends, and listen sections for:

    * ``log-format`` directives (custom format string) → PASS.
    * ``option httplog`` (built-in detailed HTTP log format) → PARTIAL.

    Returns PASS if a custom log-format is found, PARTIAL if only
    ``option httplog`` is present, FAIL if neither is found.
    """
    custom_format_parts: list[str] = []
    httplog_parts: list[str] = []

    # Check defaults
    for section in config.defaults:
        section_label = f"defaults({section.name or 'unnamed'})"
        for directive in section.get("log-format"):
            custom_format_parts.append(
                f"Custom log-format in {section_label}: {directive.args}"
            )
        for directive in section.get("option"):
            if "httplog" in directive.args.lower():
                httplog_parts.append(
                    f"option httplog in {section_label}"
                )

    # Check frontends
    for section in config.frontends:
        for directive in section.get("log-format"):
            custom_format_parts.append(
                f"Custom log-format in frontend '{section.name}': {directive.args}"
            )
        for directive in section.get("option"):
            if "httplog" in directive.args.lower():
                httplog_parts.append(
                    f"option httplog in frontend '{section.name}'"
                )

    # Check listen sections
    for section in config.listens:
        for directive in section.get("log-format"):
            custom_format_parts.append(
                f"Custom log-format in listen '{section.name}': {directive.args}"
            )
        for directive in section.get("option"):
            if "httplog" in directive.args.lower():
                httplog_parts.append(
                    f"option httplog in listen '{section.name}'"
                )

    if custom_format_parts:
        return Finding(
            check_id="HAPR-LOG-002",
            status=Status.PASS,
            message="Custom log-format is configured for detailed security logging.",
            evidence="; ".join(custom_format_parts + httplog_parts),
        )

    if httplog_parts:
        return Finding(
            check_id="HAPR-LOG-002",
            status=Status.PARTIAL,
            message=(
                "option httplog is configured but a custom log-format string "
                "would provide richer security-relevant fields (client IP, "
                "request timers, captured headers)."
            ),
            evidence="; ".join(httplog_parts),
        )

    return Finding(
        check_id="HAPR-LOG-002",
        status=Status.FAIL,
        message=(
            "No detailed log format found. The default log format is minimal "
            "and insufficient for security monitoring. Add 'option httplog' to "
            "defaults or frontends, or define a custom 'log-format' string "
            "for richer log output."
        ),
        evidence="No log-format or option httplog directives detected in defaults, frontends, or listen sections.",
    )


# NOTE: This function is no longer referenced in the baseline YAML (consolidated into access.check_stats_access_restricted)
def check_stats_secured(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-003: Check that the stats endpoint is properly secured.

    The HAProxy stats page exposes operational details that can aid
    attackers.  When enabled, it should be protected with authentication
    (``stats auth``), restricted via ACLs (``stats admin if``), and
    should hide the version string (``stats hide-version``).

    Logic:

    * If stats are not enabled anywhere -> PASS (nothing to protect).
    * If stats are enabled **with** ``stats auth`` **and**
      ``stats hide-version`` -> PASS.
    * If stats are enabled **with** ``stats auth`` but missing other
      protections -> PARTIAL.
    * If stats are enabled **without** ``stats auth`` -> FAIL.
    """
    stats_enabled = False
    has_auth = False
    has_hide_version = False
    has_admin_acl = False
    evidence_parts: list[str] = []

    # Collect all sections that could contain stats directives
    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.backends)
        + list(config.defaults)
    )

    for section in all_sections:
        section_name = getattr(section, "name", "unnamed")

        for directive in section.directives:
            keyword_lower = directive.keyword.lower()
            args_lower = directive.args.lower() if directive.args else ""

            # Detect stats enable / stats uri
            if keyword_lower == "stats":
                if args_lower.startswith("enable"):
                    stats_enabled = True
                    evidence_parts.append(f"stats enable in '{section_name}'")
                elif args_lower.startswith("uri"):
                    stats_enabled = True
                    evidence_parts.append(
                        f"stats uri in '{section_name}': stats {directive.args}"
                    )
                elif args_lower.startswith("auth"):
                    has_auth = True
                    evidence_parts.append(f"stats auth in '{section_name}'")
                elif args_lower.startswith("hide-version"):
                    has_hide_version = True
                    evidence_parts.append(f"stats hide-version in '{section_name}'")
                elif args_lower.startswith("admin"):
                    has_admin_acl = True
                    evidence_parts.append(
                        f"stats admin rule in '{section_name}': stats {directive.args}"
                    )

    # If stats are not enabled, nothing to protect
    if not stats_enabled:
        return Finding(
            check_id="HAPR-LOG-003",
            status=Status.PASS,
            message="Stats endpoint is not enabled; no exposure risk.",
            evidence="No 'stats enable' or 'stats uri' directives found.",
        )

    # Stats enabled without auth -> FAIL
    if not has_auth:
        return Finding(
            check_id="HAPR-LOG-003",
            status=Status.FAIL,
            message=(
                "Stats endpoint is enabled without authentication. "
                "Add 'stats auth <user>:<password>' to require credentials, "
                "'stats hide-version' to hide the HAProxy version, and "
                "consider restricting admin access with 'stats admin if <acl>'."
            ),
            evidence="; ".join(evidence_parts),
        )

    # Stats enabled with auth but missing other protections -> PARTIAL
    missing: list[str] = []
    if not has_hide_version:
        missing.append("stats hide-version")
    if not has_admin_acl:
        missing.append("stats admin if <acl> (admin ACL restriction)")

    if missing:
        return Finding(
            check_id="HAPR-LOG-003",
            status=Status.PARTIAL,
            message=(
                "Stats endpoint has authentication but is missing additional "
                f"protections: {', '.join(missing)}."
            ),
            evidence="; ".join(evidence_parts),
        )

    # Fully secured
    return Finding(
        check_id="HAPR-LOG-003",
        status=Status.PASS,
        message="Stats endpoint is properly secured with auth, version hiding, and admin ACL restrictions.",
        evidence="; ".join(evidence_parts),
    )


def check_log_level(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-004: Check that log directives specify an appropriate level.

    Log directives in the global section follow the format::

        log <target> <facility> [<level>]

    This check examines the log directive arguments for the specified level.

    * PASS if the level is one of: info, notice, warning, warn (good for security monitoring).
    * PASS if no explicit level is specified (HAProxy defaults are acceptable).
    * PARTIAL if the level is ``debug`` (too verbose for production).
    * PARTIAL if the level is ``emerg``, ``alert``, ``crit``, ``err``, or ``error``
      (too restrictive -- will miss security-relevant events).
    * FAIL if no log directives are found at all.
    """
    log_directives = config.global_section.get("log")

    if not log_directives:
        return Finding(
            check_id="HAPR-LOG-004",
            status=Status.FAIL,
            message=(
                "No log directives found in the global section, so no log "
                "level can be determined. Add a log directive with an "
                "appropriate level (e.g. 'log /dev/log local0 info')."
            ),
            evidence="No log directives in global section.",
        )

    # Levels that capture enough security events
    good_levels = {"info", "notice", "warning", "warn"}
    # Levels that are too restrictive for security monitoring
    restrictive_levels = {"emerg", "alert", "crit", "err", "error"}

    debug_found = False
    restrictive_found = False
    good_found = False
    evidence_parts: list[str] = []

    all_known_levels = good_levels | restrictive_levels | {"debug"}

    for directive in log_directives:
        # Typical format: "127.0.0.1:514 local0 info" or "/dev/log local0"
        tokens = directive.args.split()
        detected_level: str | None = None

        # The level, if present, is usually the third token (index 2)
        # or sometimes the second token in shorter forms.  We search all
        # tokens for a recognised level keyword.
        for token in tokens:
            if token.lower() in all_known_levels:
                detected_level = token.lower()
                break

        if detected_level == "debug":
            debug_found = True
            evidence_parts.append(f"log {directive.args} (level: debug)")
        elif detected_level in restrictive_levels:
            restrictive_found = True
            evidence_parts.append(f"log {directive.args} (level: {detected_level})")
        elif detected_level in good_levels:
            good_found = True
            evidence_parts.append(f"log {directive.args} (level: {detected_level})")
        else:
            # No explicit level -- HAProxy defaults to the facility's
            # default, which is usually acceptable.  We count it as good.
            good_found = True
            evidence_parts.append(f"log {directive.args} (no explicit level)")

    if debug_found:
        return Finding(
            check_id="HAPR-LOG-004",
            status=Status.PARTIAL,
            message=(
                "Log level is set to 'debug'. Debug logging generates "
                "excessive output and should not be used in production. "
                "Consider using 'info' or 'notice' instead."
            ),
            evidence="; ".join(evidence_parts),
        )

    if good_found:
        return Finding(
            check_id="HAPR-LOG-004",
            status=Status.PASS,
            message="Log level is set to an appropriate production level.",
            evidence="; ".join(evidence_parts),
        )

    if restrictive_found:
        return Finding(
            check_id="HAPR-LOG-004",
            status=Status.PARTIAL,
            message=(
                "Log level is too restrictive for security monitoring. "
                "Levels like emerg, alert, crit, and err will miss most "
                "security-relevant events. Consider using 'info' or 'notice' instead."
            ),
            evidence="; ".join(evidence_parts),
        )

    # Log directives exist but none specify a level explicitly
    return Finding(
        check_id="HAPR-LOG-004",
        status=Status.PASS,
        message=(
            "Log directives are present but no explicit level is specified. "
            "HAProxy defaults to an acceptable level."
        ),
        evidence="; ".join(evidence_parts),
    )


def check_httplog_or_tcplog(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-005: Check for ``option httplog`` or ``option tcplog``.

    Without ``option httplog`` or ``option tcplog``, HAProxy uses a very
    basic connection-level log format that omits HTTP request details and
    timing information.  At least one of these options should be present
    in defaults or frontend/listen sections.

    Returns PASS if found, FAIL if not.
    """
    evidence_parts: list[str] = []

    # Check defaults
    for section in config.defaults:
        section_label = f"defaults({section.name or 'unnamed'})"
        for directive in section.get("option"):
            args_lower = directive.args.lower()
            if "httplog" in args_lower:
                evidence_parts.append(f"option httplog in {section_label}")
            elif "tcplog" in args_lower:
                evidence_parts.append(f"option tcplog in {section_label}")

    # Check frontends
    for section in config.frontends:
        for directive in section.get("option"):
            args_lower = directive.args.lower()
            if "httplog" in args_lower:
                evidence_parts.append(
                    f"option httplog in frontend '{section.name}'"
                )
            elif "tcplog" in args_lower:
                evidence_parts.append(
                    f"option tcplog in frontend '{section.name}'"
                )

    # Check listen sections
    for section in config.listens:
        for directive in section.get("option"):
            args_lower = directive.args.lower()
            if "httplog" in args_lower:
                evidence_parts.append(
                    f"option httplog in listen '{section.name}'"
                )
            elif "tcplog" in args_lower:
                evidence_parts.append(
                    f"option tcplog in listen '{section.name}'"
                )

    if evidence_parts:
        return Finding(
            check_id="HAPR-LOG-005",
            status=Status.PASS,
            message="HTTP or TCP log option is configured for detailed logging.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-LOG-005",
        status=Status.FAIL,
        message=(
            "Neither 'option httplog' nor 'option tcplog' is configured. "
            "Without these, HAProxy uses a minimal log format that lacks "
            "HTTP request details and timing information. Add 'option httplog' "
            "to defaults or frontends for HTTP proxies, or 'option tcplog' "
            "for TCP-only proxies."
        ),
        evidence="No option httplog or option tcplog directives found in defaults, frontends, or listen sections.",
    )


def check_dontlognull(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-006: Check for ``option dontlognull`` directive.

    ``option dontlognull`` prevents HAProxy from logging connections that
    close without sending any data.  This filters out health-check probes,
    port scans, and other noise that would otherwise clutter the logs.

    Searches defaults, frontends, and listen sections for the directive.

    Returns
    -------
    Finding
        PASS -- ``option dontlognull`` is found in at least one section.
        FAIL -- ``option dontlognull`` is not found in any section.
    """
    evidence_parts: list[str] = []

    # Check defaults
    for section in config.defaults:
        section_label = f"defaults({section.name or 'unnamed'})"
        for directive in section.get("option"):
            if "dontlognull" in directive.args.lower():
                evidence_parts.append(f"option dontlognull in {section_label}")

    # Check frontends
    for section in config.frontends:
        for directive in section.get("option"):
            if "dontlognull" in directive.args.lower():
                evidence_parts.append(
                    f"option dontlognull in frontend '{section.name}'"
                )

    # Check listen sections
    for section in config.listens:
        for directive in section.get("option"):
            if "dontlognull" in directive.args.lower():
                evidence_parts.append(
                    f"option dontlognull in listen '{section.name}'"
                )

    if evidence_parts:
        return Finding(
            check_id="HAPR-LOG-006",
            status=Status.PASS,
            message="'option dontlognull' is configured to suppress empty connection logs.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-LOG-006",
        status=Status.FAIL,
        message=(
            "No 'option dontlognull' directive found. Without it, HAProxy "
            "logs connections that close without sending data (health checks, "
            "port scans), adding noise to log files. Add 'option dontlognull' "
            "to defaults or frontends."
        ),
        evidence="No option dontlognull directives found in defaults, frontends, or listen sections.",
    )


def check_remote_syslog(config: HAProxyConfig) -> Finding:
    """HAPR-LOG-007: Check that at least one log directive sends to a remote syslog server.

    Centralized remote logging ensures that log data survives host compromise
    and enables aggregated monitoring.  This check examines global ``log``
    directives to determine whether any target is a remote syslog endpoint
    (IP or hostname with optional port) rather than a local Unix socket
    (paths starting with ``/``).

    Returns
    -------
    Finding
        PASS    -- At least one remote syslog target is found.
        PARTIAL -- Only local syslog targets exist (e.g. ``/dev/log``).
        FAIL    -- No log directives at all.
    """
    log_directives = config.global_section.get("log")

    if not log_directives:
        return Finding(
            check_id="HAPR-LOG-007",
            status=Status.FAIL,
            message=(
                "No log directives found in the global section. "
                "Add a remote syslog target (e.g. 'log 10.0.0.1:514 local0') "
                "for centralized logging."
            ),
            evidence="No log directives in global section.",
        )

    remote_targets: list[str] = []
    local_targets: list[str] = []

    for directive in log_directives:
        # The first token of the args is the log target
        tokens = directive.args.split()
        if not tokens:
            continue
        target = tokens[0]

        if target.startswith("/"):
            local_targets.append(f"log {directive.args} (local: {target})")
        else:
            remote_targets.append(f"log {directive.args} (remote: {target})")

    if remote_targets:
        return Finding(
            check_id="HAPR-LOG-007",
            status=Status.PASS,
            message="Remote syslog target is configured for centralized logging.",
            evidence="; ".join(remote_targets + local_targets),
        )

    if local_targets:
        return Finding(
            check_id="HAPR-LOG-007",
            status=Status.PARTIAL,
            message=(
                "Only local syslog targets found. Logs sent to local sockets "
                "may be lost if the host is compromised. Add a remote syslog "
                "target (e.g. 'log 10.0.0.1:514 local0') for centralized logging."
            ),
            evidence="; ".join(local_targets),
        )

    return Finding(
        check_id="HAPR-LOG-007",
        status=Status.FAIL,
        message=(
            "No usable log targets found in the global section. "
            "Add a remote syslog target (e.g. 'log 10.0.0.1:514 local0') "
            "for centralized logging."
        ),
        evidence="Log directives found but no targets could be parsed.",
    )
