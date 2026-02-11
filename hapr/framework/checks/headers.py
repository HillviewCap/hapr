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

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "X-Frame-Options")

    if directive:
        return Finding(
            check_id="HAPR-HDR-001",
            status=Status.PASS,
            message="X-Frame-Options header is configured.",
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

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "Content-Security-Policy")

    if directive:
        return Finding(
            check_id="HAPR-HDR-002",
            status=Status.PASS,
            message="Content-Security-Policy header is configured.",
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

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "X-Content-Type-Options")

    if directive:
        return Finding(
            check_id="HAPR-HDR-003",
            status=Status.PASS,
            message="X-Content-Type-Options header is configured.",
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


def check_referrer_policy(config: HAProxyConfig) -> Finding:
    """HAPR-HDR-004: Check for Referrer-Policy header.

    The Referrer-Policy header controls how much referrer information is
    included with requests.  Setting it reduces information leakage to
    third-party sites.

    Returns PASS if the header is set, FAIL otherwise.
    """
    directive = _find_response_header(config, "Referrer-Policy")

    if directive:
        return Finding(
            check_id="HAPR-HDR-004",
            status=Status.PASS,
            message="Referrer-Policy header is configured.",
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
