"""HTTP security header checks for HAProxy configurations.

Examines ``http-response set-header`` and ``http-response add-header``
directives across frontends, listens, and defaults sections to verify
that standard security headers are being injected.
"""

from __future__ import annotations

import re

from ...models import Directive, HAProxyConfig, Finding, Status


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_header_value(directive: Directive, header_name: str) -> str:
    """Extract the header value from a response-header directive.

    The directive args look like ``"set-header X-Frame-Options DENY"``; this
    helper returns the portion after the header name (e.g. ``"DENY"``).
    """
    match = re.search(
        r"(?:set-header|add-header)\s+" + re.escape(header_name) + r"\s+(.+)",
        directive.args,
        re.IGNORECASE,
    )
    return match.group(1).strip().strip("\"'") if match else ""


def _find_response_header(
    config: HAProxyConfig, header_name: str
) -> Directive | None:
    """Search all frontends, listens, and defaults for a response header directive.

    Looks for ``http-response set-header`` or ``http-response add-header``
    directives whose first argument matches *header_name* (case-insensitive).

    Parameters
    ----------
    config:
        Parsed HAProxy configuration to search.
    header_name:
        The HTTP header name to look for (e.g. ``X-Frame-Options``).

    Returns
    -------
    The matching :class:`Directive` if found, otherwise ``None``.
    """
    # Pattern: (set-header|add-header) <Header-Name> <value...>
    # The directive keyword will be "http-response" and args will contain the rest.
    header_re = re.compile(
        r"^(?:set-header|add-header)\s+" + re.escape(header_name) + r"\s",
        re.IGNORECASE,
    )

    sections = (
        list(config.frontends)
        + list(config.listens)
        + list(config.defaults)
    )

    for section in sections:
        for directive in section.get("http-response"):
            if header_re.match(directive.args):
                return directive

    return None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_x_frame_options(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-001: Check for X-Frame-Options header.

    The X-Frame-Options header prevents clickjacking attacks by controlling
    whether the browser is allowed to render a page in a ``<frame>``,
    ``<iframe>``, or ``<object>``.  Expected values are ``DENY`` or
    ``SAMEORIGIN``.

    Returns PASS if value is DENY or SAMEORIGIN, PARTIAL if header is present
    but has an invalid value, FAIL if header is not set.
    """
    directive = _find_response_header(config, "X-Frame-Options")

    if directive:
        value = _extract_header_value(directive, "X-Frame-Options")
        if value.upper() in ("DENY", "SAMEORIGIN"):
            return Finding(
                check_id="HAPR-HDR-001",
                status=Status.PASS,
                message=f"X-Frame-Options header is configured with valid value '{value}'.",
                evidence=f"http-response {directive.args} (line {directive.line_number})",
            )
        return Finding(
            check_id="HAPR-HDR-001",
            status=Status.PARTIAL,
            message=(
                f"X-Frame-Options header is set to '{value}', which is not a "
                "recommended value. Use 'DENY' or 'SAMEORIGIN'."
            ),
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-001",
        status=Status.FAIL,
        message=(
            "X-Frame-Options header is not set. Add "
            "'http-response set-header X-Frame-Options DENY' or 'SAMEORIGIN' "
            "to prevent clickjacking attacks."
        ),
        evidence="No http-response set-header/add-header for X-Frame-Options found.",
    )


def check_csp_header(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-002: Check for Content-Security-Policy header.

    Content-Security-Policy (CSP) is the most effective mitigation against
    cross-site scripting (XSS) and data injection attacks.

    Returns PASS if header is present without dangerous patterns, PARTIAL if
    it contains ``unsafe-inline``, ``unsafe-eval``, or wildcard ``*`` sources,
    FAIL if header is not set.
    """
    directive = _find_response_header(config, "Content-Security-Policy")

    if directive:
        value = _extract_header_value(directive, "Content-Security-Policy")
        # Check for dangerous CSP patterns
        dangerous_patterns = []
        if "unsafe-inline" in value.lower():
            dangerous_patterns.append("unsafe-inline")
        if "unsafe-eval" in value.lower():
            dangerous_patterns.append("unsafe-eval")
        # Match wildcard * used as a source (e.g. "default-src *")
        if re.search(r"(?:^|\s)\*(?:\s|;|$)", value):
            dangerous_patterns.append("* (wildcard source)")

        if dangerous_patterns:
            return Finding(
                check_id="HAPR-HDR-002",
                status=Status.PARTIAL,
                message=(
                    "Content-Security-Policy header is set but contains dangerous "
                    f"patterns: {', '.join(dangerous_patterns)}."
                ),
                evidence=f"http-response {directive.args} (line {directive.line_number})",
            )

        return Finding(
            check_id="HAPR-HDR-002",
            status=Status.PASS,
            message="Content-Security-Policy header is configured with a strict policy.",
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-002",
        status=Status.FAIL,
        message=(
            "Content-Security-Policy header is not set. A CSP header helps "
            "prevent XSS and data injection attacks."
        ),
        evidence="No http-response set-header/add-header for Content-Security-Policy found.",
    )


def check_x_content_type_options(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-003: Check for X-Content-Type-Options nosniff header.

    This header prevents browsers from MIME-type sniffing a response away
    from the declared content type.  The only valid value is ``nosniff``.

    Returns PASS if value is ``nosniff``, PARTIAL if header is present with a
    different value, FAIL if header is not set.
    """
    directive = _find_response_header(config, "X-Content-Type-Options")

    if directive:
        value = _extract_header_value(directive, "X-Content-Type-Options")
        if value.lower() == "nosniff":
            return Finding(
                check_id="HAPR-HDR-003",
                status=Status.PASS,
                message="X-Content-Type-Options header is correctly set to 'nosniff'.",
                evidence=f"http-response {directive.args} (line {directive.line_number})",
            )
        return Finding(
            check_id="HAPR-HDR-003",
            status=Status.PARTIAL,
            message=(
                f"X-Content-Type-Options header is set to '{value}', but the "
                "only valid value is 'nosniff'."
            ),
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-003",
        status=Status.FAIL,
        message=(
            "X-Content-Type-Options header is not set. Add "
            "'http-response set-header X-Content-Type-Options nosniff' "
            "to prevent MIME-type sniffing."
        ),
        evidence="No http-response set-header/add-header for X-Content-Type-Options found.",
    )


_SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}

_INSECURE_REFERRER_POLICIES = {"unsafe-url", ""}


def check_referrer_policy(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-004: Check for Referrer-Policy header.

    The Referrer-Policy header controls how much referrer information is
    included with requests.  Setting it reduces information leakage to
    third-party sites.

    Returns PASS if a recognized safe policy is set, PARTIAL if the value is
    ``unsafe-url`` or empty, FAIL if the header is not set.
    """
    directive = _find_response_header(config, "Referrer-Policy")

    if directive:
        value = _extract_header_value(directive, "Referrer-Policy")
        if value.lower() in _INSECURE_REFERRER_POLICIES:
            return Finding(
                check_id="HAPR-HDR-004",
                status=Status.PARTIAL,
                message=(
                    f"Referrer-Policy header is set to '{value}', which is insecure. "
                    "Use a stricter policy such as 'strict-origin-when-cross-origin'."
                ),
                evidence=f"http-response {directive.args} (line {directive.line_number})",
            )
        return Finding(
            check_id="HAPR-HDR-004",
            status=Status.PASS,
            message=f"Referrer-Policy header is configured with value '{value}'.",
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-004",
        status=Status.FAIL,
        message=(
            "Referrer-Policy header is not set. Add "
            "'http-response set-header Referrer-Policy no-referrer' or another "
            "appropriate policy to limit referrer information leakage."
        ),
        evidence="No http-response set-header/add-header for Referrer-Policy found.",
    )


def check_permissions_policy(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-005: Check for Permissions-Policy header.

    Permissions-Policy (formerly Feature-Policy) allows a site to control
    which browser features and APIs can be used (e.g. camera, microphone,
    geolocation).

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "Permissions-Policy")

    if directive:
        return Finding(
            check_id="HAPR-HDR-005",
            status=Status.PASS,
            message="Permissions-Policy header is configured.",
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-005",
        status=Status.FAIL,
        message=(
            "Permissions-Policy header is not set. Add "
            "'http-response set-header Permissions-Policy' with an appropriate "
            "policy to control browser feature access."
        ),
        evidence="No http-response set-header/add-header for Permissions-Policy found.",
    )


def check_x_xss_protection(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-006: Check X-XSS-Protection header status.

    X-XSS-Protection is deprecated in modern browsers and can introduce
    additional vulnerabilities.  Best practice is to not set it at all
    or set it to ``0`` (explicitly disabled).

    Returns:
    - PASS if the header is absent (recommended) or explicitly set to ``0``.
    - PARTIAL if the header is set to ``1; mode=block`` (functional but
      deprecated; relies on a legacy browser feature).
    """
    directive = _find_response_header(config, "X-XSS-Protection")

    if directive is None:
        return Finding(
            check_id="HAPR-HDR-006",
            status=Status.PASS,
            message=(
                "X-XSS-Protection header is not set. This is the recommended "
                "approach as the header is deprecated in modern browsers."
            ),
            evidence="No http-response set-header/add-header for X-XSS-Protection found.",
        )

    # Extract the header value from the directive args.
    # args looks like: "set-header X-XSS-Protection <value>"
    value_match = re.search(
        r"(?:set-header|add-header)\s+X-XSS-Protection\s+(.+)",
        directive.args,
        re.IGNORECASE,
    )
    header_value = value_match.group(1).strip() if value_match else ""

    # Value "0" means explicitly disabled -- this is fine
    if header_value.strip('"\'') == "0":
        return Finding(
            check_id="HAPR-HDR-006",
            status=Status.PASS,
            message=(
                "X-XSS-Protection is explicitly set to '0', which disables "
                "the deprecated XSS auditor. This is acceptable."
            ),
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    # Any value with "1" indicates the legacy XSS auditor is active
    return Finding(
        check_id="HAPR-HDR-006",
        status=Status.PARTIAL,
        message=(
            "X-XSS-Protection is set but the header is deprecated. "
            "Modern browsers no longer support the XSS auditor. "
            "Consider removing this header or setting it to '0' and relying "
            "on Content-Security-Policy instead."
        ),
        evidence=f"http-response {directive.args} (line {directive.line_number})",
    )


def check_cross_origin_opener_policy(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-007: Check for Cross-Origin-Opener-Policy (COOP) header.

    The Cross-Origin-Opener-Policy header prevents other domains from
    opening or controlling a window.  This isolates the browsing context
    and mitigates cross-origin attacks such as Spectre.

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "Cross-Origin-Opener-Policy")

    if directive:
        return Finding(
            check_id="HAPR-HDR-007",
            status=Status.PASS,
            message="Cross-Origin-Opener-Policy header is configured.",
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-007",
        status=Status.FAIL,
        message=(
            "Cross-Origin-Opener-Policy header is not set. Add "
            "'http-response set-header Cross-Origin-Opener-Policy same-origin' "
            "to isolate the browsing context from cross-origin documents."
        ),
        evidence="No http-response set-header/add-header for Cross-Origin-Opener-Policy found.",
    )


def check_cross_origin_embedder_policy(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-008: Check for Cross-Origin-Embedder-Policy (COEP) header.

    The Cross-Origin-Embedder-Policy header prevents a document from
    loading cross-origin resources that do not explicitly grant permission.
    Combined with COOP, it enables cross-origin isolation and access to
    powerful APIs such as ``SharedArrayBuffer``.

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "Cross-Origin-Embedder-Policy")

    if directive:
        return Finding(
            check_id="HAPR-HDR-008",
            status=Status.PASS,
            message="Cross-Origin-Embedder-Policy header is configured.",
            evidence=f"http-response {directive.args} (line {directive.line_number})",
        )

    return Finding(
        check_id="HAPR-HDR-008",
        status=Status.FAIL,
        message=(
            "Cross-Origin-Embedder-Policy header is not set. Add "
            "'http-response set-header Cross-Origin-Embedder-Policy require-corp' "
            "to prevent loading of cross-origin resources without explicit permission."
        ),
        evidence="No http-response set-header/add-header for Cross-Origin-Embedder-Policy found.",
    )
