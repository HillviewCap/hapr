"""Timeout configuration checks for HAProxy configurations.

Missing or excessive timeouts can lead to denial-of-service conditions
(e.g. slowloris attacks), resource exhaustion, or dangling connections.
These checks verify that all essential timeouts are present and that
their values fall within reasonable bounds.
"""

from __future__ import annotations

import re

from ...models import HAProxyConfig, Finding, Status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUFFIX_MULTIPLIERS = {
    "ms": 1,
    "s": 1_000,
    "m": 60_000,
    "h": 3_600_000,
    "d": 86_400_000,
}

# Regex: optional digits, optional suffix
_TIMEOUT_RE = re.compile(r"^\s*(\d+)\s*(ms|s|m|h|d)?\s*$", re.IGNORECASE)


def _parse_timeout_ms(value: str) -> int | None:
    """Convert an HAProxy timeout string to milliseconds.

    Supported formats:

    * Plain integer (interpreted as milliseconds): ``"30000"``
    * Integer with suffix: ``"30s"``, ``"5m"``, ``"1h"``, ``"500ms"``, ``"1d"``

    Returns ``None`` when *value* cannot be parsed.

    Parameters
    ----------
    value:
        The raw timeout value string from the configuration.

    Returns
    -------
    int | None
        Timeout in milliseconds, or ``None`` if the value is invalid.
    """
    match = _TIMEOUT_RE.match(value.strip())
    if not match:
        return None

    amount = int(match.group(1))
    suffix = (match.group(2) or "ms").lower()
    multiplier = _SUFFIX_MULTIPLIERS.get(suffix)

    if multiplier is None:
        return None

    return amount * multiplier


def _find_timeout(config: HAProxyConfig, timeout_name: str, *, include_frontends: bool = False) -> list[tuple[str, str, str]]:
    """Search for a specific timeout directive across config sections.

    Parameters
    ----------
    config:
        Parsed HAProxy configuration.
    timeout_name:
        The timeout keyword to look for, e.g. ``"client"``, ``"server"``.
    include_frontends:
        When True, also search frontends and listen sections.

    Returns
    -------
    list[tuple[str, str, str]]
        List of ``(section_kind, section_name, raw_value)`` tuples where the
        timeout was found.
    """
    results: list[tuple[str, str, str]] = []

    # Always search global and defaults
    for d in config.global_section.directives:
        if d.keyword.lower() == "timeout" and d.args.lower().split()[0] == timeout_name:
            parts = d.args.strip().split(None, 1)
            raw_val = parts[1] if len(parts) > 1 else ""
            results.append(("global", "", raw_val))

    for ds in config.defaults:
        for d in ds.directives:
            if d.keyword.lower() == "timeout" and d.args.lower().split()[0] == timeout_name:
                parts = d.args.strip().split(None, 1)
                raw_val = parts[1] if len(parts) > 1 else ""
                results.append(("defaults", ds.name or "(unnamed)", raw_val))

    if include_frontends:
        for fe in config.frontends:
            for d in fe.directives:
                if d.keyword.lower() == "timeout" and d.args.lower().split()[0] == timeout_name:
                    parts = d.args.strip().split(None, 1)
                    raw_val = parts[1] if len(parts) > 1 else ""
                    results.append(("frontend", fe.name, raw_val))

        for ls in config.listens:
            for d in ls.directives:
                if d.keyword.lower() == "timeout" and d.args.lower().split()[0] == timeout_name:
                    parts = d.args.strip().split(None, 1)
                    raw_val = parts[1] if len(parts) > 1 else ""
                    results.append(("listen", ls.name, raw_val))

    return results


# ---------------------------------------------------------------------------
# HAPR-TMO-001 — client timeout
# ---------------------------------------------------------------------------

def check_client_timeout(config: HAProxyConfig) -> Finding:
    """Check that ``timeout client`` is configured.

    The client timeout governs how long HAProxy waits for data from the
    client side of a connection.  Without it, idle client connections
    may consume resources indefinitely.

    Returns
    -------
    Finding
        PASS -- ``timeout client`` is set in defaults or global.
        FAIL -- ``timeout client`` is not configured.
    """
    hits = _find_timeout(config, "client")

    if hits:
        evidence = "; ".join(
            f"{kind} '{name}': timeout client {val}" if name else f"{kind}: timeout client {val}"
            for kind, name, val in hits
        )
        return Finding(
            check_id="HAPR-TMO-001",
            status=Status.PASS,
            message="Client timeout is configured.",
            evidence=evidence,
        )

    return Finding(
        check_id="HAPR-TMO-001",
        status=Status.FAIL,
        message=(
            "No 'timeout client' directive found in defaults or global. "
            "Idle client connections may exhaust resources."
        ),
        evidence="timeout client not found in global or defaults sections.",
    )


# ---------------------------------------------------------------------------
# HAPR-TMO-002 — server timeout
# ---------------------------------------------------------------------------

def check_server_timeout(config: HAProxyConfig) -> Finding:
    """Check that ``timeout server`` is configured.

    The server timeout governs how long HAProxy waits for a response
    from a backend server.  A missing server timeout can lead to
    connections hanging indefinitely when a backend becomes unresponsive.

    Returns
    -------
    Finding
        PASS -- ``timeout server`` is set in defaults or global.
        FAIL -- ``timeout server`` is not configured.
    """
    hits = _find_timeout(config, "server")

    if hits:
        evidence = "; ".join(
            f"{kind} '{name}': timeout server {val}" if name else f"{kind}: timeout server {val}"
            for kind, name, val in hits
        )
        return Finding(
            check_id="HAPR-TMO-002",
            status=Status.PASS,
            message="Server timeout is configured.",
            evidence=evidence,
        )

    return Finding(
        check_id="HAPR-TMO-002",
        status=Status.FAIL,
        message=(
            "No 'timeout server' directive found in defaults or global. "
            "Unresponsive backends may cause connections to hang indefinitely."
        ),
        evidence="timeout server not found in global or defaults sections.",
    )


# ---------------------------------------------------------------------------
# HAPR-TMO-003 — connect timeout
# ---------------------------------------------------------------------------

def check_connect_timeout(config: HAProxyConfig) -> Finding:
    """Check that ``timeout connect`` is configured.

    The connect timeout limits how long HAProxy will wait when
    establishing a TCP connection to a backend server.

    Returns
    -------
    Finding
        PASS -- ``timeout connect`` is set in defaults or global.
        FAIL -- ``timeout connect`` is not configured.
    """
    hits = _find_timeout(config, "connect")

    if hits:
        evidence = "; ".join(
            f"{kind} '{name}': timeout connect {val}" if name else f"{kind}: timeout connect {val}"
            for kind, name, val in hits
        )
        return Finding(
            check_id="HAPR-TMO-003",
            status=Status.PASS,
            message="Connect timeout is configured.",
            evidence=evidence,
        )

    return Finding(
        check_id="HAPR-TMO-003",
        status=Status.FAIL,
        message=(
            "No 'timeout connect' directive found in defaults or global. "
            "Connection attempts to unresponsive backends may block indefinitely."
        ),
        evidence="timeout connect not found in global or defaults sections.",
    )


# ---------------------------------------------------------------------------
# HAPR-TMO-004 — http-request timeout
# ---------------------------------------------------------------------------

def check_http_request_timeout(config: HAProxyConfig) -> Finding:
    """Check that ``timeout http-request`` is configured.

    The ``http-request`` timeout limits the time allowed to receive a
    complete HTTP request (headers).  This is a critical defense against
    *slowloris*-style denial-of-service attacks that send headers very
    slowly to tie up connections.

    Returns
    -------
    Finding
        PASS -- ``timeout http-request`` is configured.
        FAIL -- ``timeout http-request`` is not found.
    """
    hits = _find_timeout(config, "http-request", include_frontends=True)

    if hits:
        evidence = "; ".join(
            f"{kind} '{name}': timeout http-request {val}" if name else f"{kind}: timeout http-request {val}"
            for kind, name, val in hits
        )
        return Finding(
            check_id="HAPR-TMO-004",
            status=Status.PASS,
            message="HTTP request timeout is configured (slowloris protection).",
            evidence=evidence,
        )

    return Finding(
        check_id="HAPR-TMO-004",
        status=Status.FAIL,
        message=(
            "No 'timeout http-request' directive found. Without this timeout, "
            "the server is vulnerable to slowloris-style denial-of-service attacks."
        ),
        evidence="timeout http-request not found in defaults, global, frontends, or listen sections.",
    )


# ---------------------------------------------------------------------------
# HAPR-TMO-005 — timeout values are reasonable
# ---------------------------------------------------------------------------

# Thresholds (in milliseconds)
_MAX_CLIENT_MS = 300_000       # 5 minutes
_MAX_SERVER_MS = 300_000       # 5 minutes
_MAX_CONNECT_MS = 30_000       # 30 seconds
_MAX_HTTP_REQUEST_MS = 30_000  # 30 seconds
_EXTREME_THRESHOLD_MS = 600_000  # 10 minutes — anything above is extreme

_TIMEOUT_LIMITS: dict[str, tuple[int, bool]] = {
    # timeout_name: (max_reasonable_ms, include_frontends)
    "client": (_MAX_CLIENT_MS, False),
    "server": (_MAX_SERVER_MS, False),
    "connect": (_MAX_CONNECT_MS, False),
    "http-request": (_MAX_HTTP_REQUEST_MS, True),
}


def check_timeout_values_reasonable(config: HAProxyConfig) -> Finding:
    """Check that configured timeout values are not excessively long.

    Overly generous timeouts increase exposure to slow-read/slow-write
    attacks and waste connection resources.

    Thresholds
    ----------
    * ``client`` / ``server``:  <= 300 s (5 min)
    * ``connect``:              <= 30 s
    * ``http-request``:         <= 30 s
    * Values >= 600 s (10 min) are considered *extremely* long.

    Returns
    -------
    Finding
        PASS    -- All timeout values are within reasonable bounds.
        PARTIAL -- Some timeouts exceed recommended limits.
        FAIL    -- Timeouts are extremely long (>600 s) or entirely missing.
    """
    issues: list[str] = []
    extreme_issues: list[str] = []
    ok_parts: list[str] = []
    missing: list[str] = []

    for timeout_name, (max_ms, incl_fe) in _TIMEOUT_LIMITS.items():
        hits = _find_timeout(config, timeout_name, include_frontends=incl_fe)

        if not hits:
            missing.append(timeout_name)
            continue

        for kind, name, raw_val in hits:
            ms = _parse_timeout_ms(raw_val)
            section_label = f"{kind} '{name}'" if name else kind

            if ms is None:
                issues.append(
                    f"{section_label}: timeout {timeout_name} {raw_val} (unparseable)"
                )
                continue

            if ms >= _EXTREME_THRESHOLD_MS:
                extreme_issues.append(
                    f"{section_label}: timeout {timeout_name} {raw_val} "
                    f"({ms}ms > {_EXTREME_THRESHOLD_MS}ms extreme threshold)"
                )
            elif ms > max_ms:
                issues.append(
                    f"{section_label}: timeout {timeout_name} {raw_val} "
                    f"({ms}ms > {max_ms}ms recommended max)"
                )
            else:
                ok_parts.append(
                    f"{section_label}: timeout {timeout_name} {raw_val} ({ms}ms)"
                )

    # Determine overall status
    all_evidence = []
    if ok_parts:
        all_evidence.append("OK: " + "; ".join(ok_parts))
    if issues:
        all_evidence.append("Too long: " + "; ".join(issues))
    if extreme_issues:
        all_evidence.append("Extreme: " + "; ".join(extreme_issues))
    if missing:
        all_evidence.append("Missing: " + ", ".join(missing))

    evidence_str = " | ".join(all_evidence)

    # FAIL: extreme values or everything is missing
    if extreme_issues or len(missing) == len(_TIMEOUT_LIMITS):
        return Finding(
            check_id="HAPR-TMO-005",
            status=Status.FAIL,
            message=(
                "Timeout values are critically misconfigured. "
                + (
                    f"Extremely long timeouts found: {'; '.join(extreme_issues)}. "
                    if extreme_issues
                    else ""
                )
                + (
                    f"All essential timeouts are missing ({', '.join(missing)})."
                    if len(missing) == len(_TIMEOUT_LIMITS)
                    else ""
                )
            ),
            evidence=evidence_str,
        )

    # PARTIAL: some too long or some missing
    if issues or missing:
        problems = []
        if issues:
            problems.append(f"{len(issues)} timeout(s) exceed recommended limits")
        if missing:
            problems.append(f"{len(missing)} timeout(s) missing ({', '.join(missing)})")
        return Finding(
            check_id="HAPR-TMO-005",
            status=Status.PARTIAL,
            message=f"Timeout values partially acceptable: {'; '.join(problems)}.",
            evidence=evidence_str,
        )

    # PASS
    return Finding(
        check_id="HAPR-TMO-005",
        status=Status.PASS,
        message="All configured timeout values are within reasonable bounds.",
        evidence=evidence_str,
    )
