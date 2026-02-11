"""Information disclosure checks for HAProxy configurations.

These checks detect configurations that may leak server software versions,
internal architecture details, or other sensitive information to clients.
"""

from __future__ import annotations

import re

from ...models import HAProxyConfig, Finding, Status


# ---- HAPR-INF-001 --------------------------------------------------------

def check_server_header_removed(config: HAProxyConfig) -> Finding:
    """Check that the ``Server`` response header is removed or overwritten.

    HAProxy (and backend servers) will by default include a ``Server``
    header that reveals the software name and version.  This check looks
    for ``http-response del-header Server``, ``http-response set-header
    Server <custom>``, or the legacy ``rspidel``/``rspdel`` directives
    targeting the Server header in *defaults*, *frontends*, or *listen*
    sections.

    Returns
    -------
    Finding
        PASS  -- Server header is handled in at least one applicable section.
        FAIL  -- No directive found to suppress or rewrite the Server header.
    """
    evidence_parts: list[str] = []

    # Sections to inspect: defaults, frontends, listens
    sections = []
    for d in config.defaults:
        sections.append(("defaults", d.name or "(unnamed)", d.directives))
    for fe in config.frontends:
        sections.append(("frontend", fe.name, fe.directives))
    for ls in config.listens:
        sections.append(("listen", ls.name, ls.directives))

    found = False
    for kind, name, directives in sections:
        for d in directives:
            kw = d.keyword.lower()
            args_lower = d.args.lower()

            # Modern syntax: http-response del-header Server
            if kw == "http-response" and re.search(
                r"del-header\s+server\b", args_lower
            ):
                evidence_parts.append(
                    f"{kind} '{name}': http-response del-header Server"
                )
                found = True

            # Modern syntax: http-response set-header Server <value>
            if kw == "http-response" and re.search(
                r"set-header\s+server\b", args_lower
            ):
                evidence_parts.append(
                    f"{kind} '{name}': http-response set-header Server (custom value)"
                )
                found = True

            # Legacy syntax: rspidel / rspdel ^Server
            if kw in ("rspidel", "rspdel") and re.search(
                r"\^?\s*server", args_lower
            ):
                evidence_parts.append(
                    f"{kind} '{name}': {d.keyword} {d.args}"
                )
                found = True

    if found:
        return Finding(
            check_id="HAPR-INF-001",
            status=Status.PASS,
            message="Server response header is removed or overwritten.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-INF-001",
        status=Status.FAIL,
        message=(
            "No directive found to remove or overwrite the Server response "
            "header. Backend software versions may be exposed to clients."
        ),
        evidence="No http-response del-header/set-header Server or rspidel/rspdel directive found.",
    )


# ---- HAPR-INF-002 --------------------------------------------------------

_COMMON_ERROR_CODES = {"400", "403", "404", "408", "500", "502", "503", "504"}


def check_custom_error_pages(config: HAProxyConfig) -> Finding:
    """Check that custom error pages are configured for common HTTP codes.

    Default HAProxy error pages reveal the software name and version.
    This check looks for ``errorfile`` directives in *defaults*,
    *frontends*, and *listen* sections for the common error codes:
    400, 403, 404, 408, 500, 502, 503, 504.

    Returns
    -------
    Finding
        PASS    -- At least 3 custom error pages are configured.
        PARTIAL -- 1-2 custom error pages are configured.
        FAIL    -- No custom error pages are configured.
    """
    configured_codes: set[str] = set()
    evidence_parts: list[str] = []

    sections = []
    for d in config.defaults:
        sections.append(("defaults", d.name or "(unnamed)", d.directives))
    for fe in config.frontends:
        sections.append(("frontend", fe.name, fe.directives))
    for ls in config.listens:
        sections.append(("listen", ls.name, ls.directives))

    for kind, name, directives in sections:
        for d in directives:
            if d.keyword.lower() == "errorfile":
                # errorfile <code> <file>
                parts = d.args.strip().split()
                if parts:
                    code = parts[0]
                    if code in _COMMON_ERROR_CODES:
                        configured_codes.add(code)
                        evidence_parts.append(
                            f"{kind} '{name}': errorfile {d.args.strip()}"
                        )

    count = len(configured_codes)
    missing = _COMMON_ERROR_CODES - configured_codes

    if count >= 3:
        return Finding(
            check_id="HAPR-INF-002",
            status=Status.PASS,
            message=(
                f"Custom error pages configured for {count} common error "
                f"codes: {', '.join(sorted(configured_codes))}."
            ),
            evidence="; ".join(evidence_parts),
        )

    if count >= 1:
        return Finding(
            check_id="HAPR-INF-002",
            status=Status.PARTIAL,
            message=(
                f"Only {count} custom error page(s) configured "
                f"({', '.join(sorted(configured_codes))}). "
                f"Missing: {', '.join(sorted(missing))}."
            ),
            evidence="; ".join(evidence_parts) if evidence_parts else "Limited errorfile directives.",
        )

    return Finding(
        check_id="HAPR-INF-002",
        status=Status.FAIL,
        message=(
            "No custom error pages configured. Default HAProxy error pages "
            "expose software name and version information."
        ),
        evidence="No errorfile directives found for common HTTP error codes.",
    )


# ---- HAPR-INF-003 --------------------------------------------------------

# Headers that commonly reveal version or technology information.
_VERSION_HEADERS = [
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-version",
    "x-generator",
]


def check_version_hidden(config: HAProxyConfig) -> Finding:
    """Check that version-revealing response headers are removed.

    Frameworks and application servers frequently add headers such as
    ``X-Powered-By`` and ``X-AspNet-Version`` that disclose the
    technology stack.  This check looks for ``http-response del-header``
    directives that strip these headers.  It also checks whether
    ``option forwardfor`` uses a custom ``header`` option (to avoid
    leaking internal addressing under the default ``X-Forwarded-For``
    name is acceptable, but a custom name reduces fingerprinting risk).

    Returns
    -------
    Finding
        PASS    -- Version-revealing headers are being removed.
        PARTIAL -- Some version headers are cleaned but coverage is incomplete.
        FAIL    -- No version header cleanup directives found.
    """
    removed_headers: set[str] = set()
    evidence_parts: list[str] = []

    sections = []
    for d in config.defaults:
        sections.append(("defaults", d.name or "(unnamed)", d.directives))
    for fe in config.frontends:
        sections.append(("frontend", fe.name, fe.directives))
    for ls in config.listens:
        sections.append(("listen", ls.name, ls.directives))

    for kind, name, directives in sections:
        for d in directives:
            kw = d.keyword.lower()
            args_lower = d.args.lower()

            # http-response del-header <header>
            if kw == "http-response":
                match = re.search(r"del-header\s+(\S+)", args_lower)
                if match:
                    header_name = match.group(1).lower()
                    if header_name in _VERSION_HEADERS:
                        removed_headers.add(header_name)
                        evidence_parts.append(
                            f"{kind} '{name}': http-response del-header {match.group(1)}"
                        )

            # option forwardfor with custom header
            if kw == "option" and args_lower.startswith("forwardfor"):
                if "header" in args_lower:
                    evidence_parts.append(
                        f"{kind} '{name}': option forwardfor with custom header"
                    )

    count = len(removed_headers)

    if count >= 2:
        return Finding(
            check_id="HAPR-INF-003",
            status=Status.PASS,
            message=(
                f"Version-revealing headers are being removed: "
                f"{', '.join(sorted(removed_headers))}."
            ),
            evidence="; ".join(evidence_parts),
        )

    if count >= 1 or evidence_parts:
        return Finding(
            check_id="HAPR-INF-003",
            status=Status.PARTIAL,
            message=(
                f"Some version headers are cleaned ({', '.join(sorted(removed_headers)) or 'none explicitly'}) "
                f"but additional headers may still leak technology details. "
                f"Consider removing: {', '.join(h for h in _VERSION_HEADERS if h not in removed_headers)}."
            ),
            evidence="; ".join(evidence_parts) if evidence_parts else "Partial header cleanup detected.",
        )

    return Finding(
        check_id="HAPR-INF-003",
        status=Status.FAIL,
        message=(
            "No directives found to remove version-revealing response "
            "headers (X-Powered-By, X-AspNet-Version, etc.). Technology "
            "stack details may be exposed to clients."
        ),
        evidence="No http-response del-header directives for version headers found.",
    )


# ---- HAPR-INF-004 --------------------------------------------------------

def check_stats_version_hidden(config: HAProxyConfig) -> Finding:
    """Check that the HAProxy stats page hides the version number.

    When the statistics page is enabled (``stats enable`` or ``stats uri``),
    the HAProxy version is displayed by default.  The ``stats hide-version``
    directive suppresses it.

    Returns
    -------
    Finding
        PASS -- Stats page is not enabled, or ``stats hide-version`` is set.
        FAIL -- Stats page is enabled without ``stats hide-version``.
    """
    stats_enabled = False
    hide_version_set = False
    stats_sections: list[str] = []
    evidence_parts: list[str] = []

    # Check all sections that can host stats directives
    sections = []
    for d in config.defaults:
        sections.append(("defaults", d.name or "(unnamed)", d))
    for fe in config.frontends:
        sections.append(("frontend", fe.name, fe))
    for ls in config.listens:
        sections.append(("listen", ls.name, ls))

    for kind, name, section in sections:
        has_stats = False
        has_hide = False
        for d in section.directives:
            kw = d.keyword.lower()
            args_lower = d.args.lower().strip()

            # stats enable
            if kw == "stats" and args_lower == "enable":
                has_stats = True

            # stats uri <path>  (implicitly enables stats)
            if kw == "stats" and args_lower.startswith("uri"):
                has_stats = True

            # stats hide-version
            if kw == "stats" and args_lower == "hide-version":
                has_hide = True

        if has_stats:
            stats_enabled = True
            stats_sections.append(f"{kind} '{name}'")
            evidence_parts.append(f"{kind} '{name}': stats enabled")
            if has_hide:
                hide_version_set = True
                evidence_parts.append(f"{kind} '{name}': stats hide-version set")

    if not stats_enabled:
        return Finding(
            check_id="HAPR-INF-004",
            status=Status.PASS,
            message="Stats page is not enabled; no version disclosure risk.",
            evidence="No stats enable or stats uri directives found.",
        )

    if hide_version_set:
        return Finding(
            check_id="HAPR-INF-004",
            status=Status.PASS,
            message="Stats page is enabled with version hidden.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-INF-004",
        status=Status.FAIL,
        message=(
            f"Stats page is enabled in {', '.join(stats_sections)} without "
            f"'stats hide-version'. The HAProxy version number is exposed."
        ),
        evidence="; ".join(evidence_parts),
    )


# ---- HAPR-INF-005 --------------------------------------------------------

def check_xff_spoofing_prevention(config: HAProxyConfig) -> Finding:
    """Check that X-Forwarded-For header spoofing is prevented.

    When ``option forwardfor`` is enabled, HAProxy appends the client IP
    to the ``X-Forwarded-For`` header.  However, an attacker can inject a
    fake ``X-Forwarded-For`` value in the original request.  Best practice
    is to delete or overwrite the header before HAProxy sets it:

    * ``http-request del-header X-Forwarded-For`` -- strongest protection.
    * ``http-request set-header X-Forwarded-For %[src]`` -- resets to the
      real client IP.
    * ``option forwardfor if-none`` -- only sets the header if it is not
      already present (weaker, but documented).

    Returns
    -------
    Finding
        PASS           -- XFF is deleted/reset before ``option forwardfor``.
        PARTIAL        -- ``option forwardfor if-none`` is used.
        FAIL           -- ``option forwardfor`` is used without prevention.
        NOT_APPLICABLE -- ``option forwardfor`` is not used at all.
    """
    forwardfor_found = False
    if_none_found = False
    xff_reset_found = False
    evidence_parts: list[str] = []

    sections: list[tuple[str, str, Any]] = []
    for d in config.defaults:
        sections.append(("defaults", d.name or "(unnamed)", d))
    for fe in config.frontends:
        sections.append(("frontend", fe.name, fe))
    for ls in config.listens:
        sections.append(("listen", ls.name, ls))

    for kind, name, section in sections:
        # Check for option forwardfor
        for directive in section.get("option"):
            args_lower = directive.args.lower()
            if args_lower.startswith("forwardfor"):
                forwardfor_found = True
                if "if-none" in args_lower:
                    if_none_found = True
                    evidence_parts.append(
                        f"{kind} '{name}': option forwardfor if-none "
                        f"(line {directive.line_number})"
                    )
                else:
                    evidence_parts.append(
                        f"{kind} '{name}': option {directive.args} "
                        f"(line {directive.line_number})"
                    )

        # Check for http-request del-header or set-header for X-Forwarded-For
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if re.search(r"del-header\s+x-forwarded-for\b", args_lower):
                xff_reset_found = True
                evidence_parts.append(
                    f"{kind} '{name}': http-request del-header X-Forwarded-For "
                    f"(line {directive.line_number})"
                )
            if re.search(r"set-header\s+x-forwarded-for\s+%\[src\]", args_lower):
                xff_reset_found = True
                evidence_parts.append(
                    f"{kind} '{name}': http-request set-header X-Forwarded-For %[src] "
                    f"(line {directive.line_number})"
                )

    if not forwardfor_found:
        return Finding(
            check_id="HAPR-INF-005",
            status=Status.NOT_APPLICABLE,
            message="option forwardfor is not used; XFF spoofing check not applicable.",
            evidence="No option forwardfor directives found in any section.",
        )

    if xff_reset_found:
        return Finding(
            check_id="HAPR-INF-005",
            status=Status.PASS,
            message=(
                "X-Forwarded-For header is deleted or reset before being set by "
                "option forwardfor, preventing spoofing."
            ),
            evidence="; ".join(evidence_parts),
        )

    if if_none_found:
        return Finding(
            check_id="HAPR-INF-005",
            status=Status.PARTIAL,
            message=(
                "option forwardfor if-none is used, which avoids overriding an "
                "existing XFF header but does not delete spoofed values. Consider "
                "adding 'http-request del-header X-Forwarded-For' or "
                "'http-request set-header X-Forwarded-For %[src]' for stronger "
                "protection."
            ),
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-INF-005",
        status=Status.FAIL,
        message=(
            "option forwardfor is used without XFF spoofing prevention. "
            "Clients can inject arbitrary X-Forwarded-For values. Add "
            "'http-request del-header X-Forwarded-For' or "
            "'http-request set-header X-Forwarded-For %[src]' before "
            "option forwardfor to prevent spoofing."
        ),
        evidence="; ".join(evidence_parts),
    )
