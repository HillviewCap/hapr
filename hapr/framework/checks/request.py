"""Request handling security checks for HAProxy configurations.

Checks cover request body size limits, URL length restrictions,
HTTP method filtering, and request header size tuning.
"""

from __future__ import annotations

from ...models import HAProxyConfig, Finding, Status


def check_max_body_size(config: HAProxyConfig) -> Finding:
    """HAPR-REQ-001: Check for request body size limits.

    Verifies that the configuration restricts the maximum request body size
    to prevent denial-of-service attacks via oversized payloads.  Looks for:

    * ``http-request deny if { req.body_size gt ...}`` rules in
      frontends, backends, or listen sections.
    * ``option http-buffer-request`` combined with ``tune.bufsize`` in
      global, which together impose an implicit body size cap.
    * ``tune.bufsize`` alone in global (provides a buffer ceiling).

    Returns a PASS finding when at least one body size limiting mechanism is
    detected, otherwise FAIL.
    """
    evidence_parts: list[str] = []

    # Check for explicit body size deny rules in proxy sections
    for section in config.all_frontends_and_listens + config.backends:
        section_name = getattr(section, "name", "unnamed")
        for directive in section.get("http-request"):
            if "req.body_size" in directive.args and "deny" in directive.args:
                evidence_parts.append(
                    f"Body size deny rule in '{section_name}': "
                    f"http-request {directive.args}"
                )

    # Check for option http-buffer-request (works with tune.bufsize)
    http_buffer_sections: list[str] = []
    for section in config.all_frontends_and_listens + config.backends:
        section_name = getattr(section, "name", "unnamed")
        if section.has("option"):
            for opt in section.get("option"):
                if "http-buffer-request" in opt.args:
                    http_buffer_sections.append(section_name)

    for section in config.defaults:
        if section.has("option"):
            for opt in section.get("option"):
                if "http-buffer-request" in opt.args:
                    http_buffer_sections.append(f"defaults({section.name or 'unnamed'})")

    # Check for tune.bufsize in global
    tune_bufsize = config.global_section.get_value("tune.bufsize")
    if tune_bufsize:
        evidence_parts.append(f"Global tune.bufsize set to {tune_bufsize}")
        if http_buffer_sections:
            evidence_parts.append(
                f"option http-buffer-request enabled in: "
                f"{', '.join(http_buffer_sections)}"
            )

    if evidence_parts:
        return Finding(
            check_id="HAPR-REQ-001",
            status=Status.PASS,
            message="Request body size limits are configured.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-REQ-001",
        status=Status.FAIL,
        message=(
            "No request body size limits found. Consider adding "
            "'http-request deny if { req.body_size gt <size> }' rules "
            "or using 'option http-buffer-request' with 'tune.bufsize' "
            "to limit request body sizes."
        ),
        evidence="No body size deny rules, tune.bufsize, or http-buffer-request directives detected.",
    )


def check_url_length_limits(config: HAProxyConfig) -> Finding:
    """HAPR-REQ-002: Check for URL length restrictions.

    Oversized URLs can be used for buffer overflow attacks or to exploit
    parser vulnerabilities.  This check looks for:

    * ``http-request deny if { url_len gt ...}`` rules.
    * ``http-request deny if { path_len gt ...}`` rules.
    * ``tune.http.maxuri`` in the global section.

    Note: ``tune.maxrewrite`` controls buffer space for header rewriting,
    not URL length, and is therefore excluded from this check.

    Returns PASS if any URL/path length restriction is found, FAIL otherwise.
    """
    evidence_parts: list[str] = []

    # Check proxy sections for url_len / path_len deny rules
    for section in config.all_frontends_and_listens + config.backends:
        section_name = getattr(section, "name", "unnamed")
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" in args_lower and (
                "url_len" in args_lower or "path_len" in args_lower
            ):
                evidence_parts.append(
                    f"URL/path length deny rule in '{section_name}': "
                    f"http-request {directive.args}"
                )

    # Also check defaults
    for section in config.defaults:
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" in args_lower and (
                "url_len" in args_lower or "path_len" in args_lower
            ):
                evidence_parts.append(
                    f"URL/path length deny rule in defaults "
                    f"'{section.name or 'unnamed'}': http-request {directive.args}"
                )

    # Check for tune.http.maxuri in global (real URL length limit)
    tune_http_maxuri = config.global_section.get_value("tune.http.maxuri")
    if tune_http_maxuri:
        evidence_parts.append(f"Global tune.http.maxuri set to {tune_http_maxuri}")

    if evidence_parts:
        return Finding(
            check_id="HAPR-REQ-002",
            status=Status.PASS,
            message="URL length restrictions are configured.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-REQ-002",
        status=Status.FAIL,
        message=(
            "No URL length restrictions found. Consider adding "
            "'http-request deny if { url_len gt <limit> }' or "
            "'http-request deny if { path_len gt <limit> }' rules, or "
            "setting 'tune.http.maxuri' in the global section."
        ),
        evidence="No url_len, path_len deny rules, or tune.http.maxuri directive detected.",
    )


def check_method_filtering(config: HAProxyConfig) -> Finding:
    """HAPR-REQ-003: Check for HTTP method restrictions.

    Allowing arbitrary HTTP methods can widen the attack surface.  This
    check verifies that the configuration restricts which methods are
    accepted.  It searches for:

    * ``http-request deny`` rules that reference ``method`` (e.g.
      ``http-request deny if !{ method GET } !{ method POST } !{ method HEAD }``).
    * ACL definitions that reference ``method`` combined with deny rules.

    Returns PASS if HTTP method filtering is found, FAIL otherwise.
    """
    evidence_parts: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.backends)
        + list(config.defaults)
    )

    for section in all_sections:
        section_name = getattr(section, "name", "unnamed")

        # Check for http-request deny rules that reference method
        for directive in section.get("http-request"):
            if "method" in directive.args.lower() and "deny" in directive.args.lower():
                evidence_parts.append(
                    f"Method filtering rule in '{section_name}': "
                    f"http-request {directive.args}"
                )

        # Check for ACL definitions referencing method
        acl_has_method = False
        method_acl_names: list[str] = []
        for directive in section.get("acl"):
            if "method" in directive.args.lower():
                acl_has_method = True
                # The ACL name is the first token in the args
                acl_name = directive.args.split()[0] if directive.args else ""
                if acl_name:
                    method_acl_names.append(acl_name)

        # If there are method ACLs, check if they are used in deny rules
        if acl_has_method:
            for directive in section.get("http-request"):
                args_lower = directive.args.lower()
                if "deny" in args_lower:
                    for acl_name in method_acl_names:
                        if acl_name.lower() in args_lower:
                            evidence_parts.append(
                                f"Method ACL '{acl_name}' used in deny rule "
                                f"in '{section_name}': http-request {directive.args}"
                            )

    if evidence_parts:
        return Finding(
            check_id="HAPR-REQ-003",
            status=Status.PASS,
            message="HTTP method filtering is configured.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-REQ-003",
        status=Status.FAIL,
        message=(
            "No HTTP method filtering found. Consider restricting allowed "
            "methods with rules like 'http-request deny if !{ method GET } "
            "!{ method POST } !{ method HEAD }' to reduce the attack surface."
        ),
        evidence="No method-based deny rules or method ACLs with deny actions detected.",
    )


def check_request_header_limits(config: HAProxyConfig) -> Finding:
    """HAPR-REQ-004: Check for request header size tuning.

    Without explicit header size tuning, HAProxy uses default buffer sizes
    that may be too generous and allow oversized headers.  This check looks
    for the following global tuning parameters:

    * ``tune.http.maxhdr`` -- limits the number of headers in a request.
    * ``tune.bufsize`` -- sets the global buffer size, which provides an
      implicit constraint on total header size (PARTIAL).

    Note: ``tune.maxrewrite`` controls buffer space reserved for header
    rewriting, not request header limits, and is excluded from this check.

    Returns PASS if ``tune.http.maxhdr`` is set.
    Returns PARTIAL if only ``tune.bufsize`` is set (implicit limit).
    Returns FAIL if neither is set.
    """
    evidence_parts: list[str] = []

    tune_http_maxhdr = config.global_section.get_value("tune.http.maxhdr")
    if tune_http_maxhdr:
        evidence_parts.append(f"tune.http.maxhdr = {tune_http_maxhdr}")

    tune_bufsize = config.global_section.get_value("tune.bufsize")
    if tune_bufsize:
        evidence_parts.append(f"tune.bufsize = {tune_bufsize}")

    if tune_http_maxhdr:
        return Finding(
            check_id="HAPR-REQ-004",
            status=Status.PASS,
            message="Request header size tuning is configured in the global section.",
            evidence="Global settings: " + ", ".join(evidence_parts),
        )

    if tune_bufsize:
        return Finding(
            check_id="HAPR-REQ-004",
            status=Status.PARTIAL,
            message=(
                "tune.bufsize is set which provides an implicit header size limit, "
                "but tune.http.maxhdr should also be set for explicit header count control."
            ),
            evidence="Global settings: " + ", ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-REQ-004",
        status=Status.FAIL,
        message=(
            "No request header size tuning found in the global section. "
            "Consider setting 'tune.http.maxhdr' to limit the number of "
            "request headers and 'tune.bufsize' to constrain total header "
            "size to mitigate oversized-header attacks."
        ),
        evidence="No tune.http.maxhdr or tune.bufsize directives found in global.",
    )


def check_http_smuggling_prevention(config: HAProxyConfig) -> Finding:
    """HAPR-REQ-005: Check for HTTP request smuggling prevention measures.

    HTTP request smuggling exploits discrepancies in how front-end and
    back-end servers parse HTTP requests.  This check looks for several
    mitigation measures:

    * ``option httpclose`` -- forces connection close after each request.
    * ``option http-use-htx`` -- enables the HTX internal representation
      which has stronger parsing and smuggling resistance.
    * ``http-request deny`` rules that reject duplicate ``Content-Length``
      or ``Transfer-Encoding`` headers.
    * ``option http-restrict-req-hdr-names reject`` -- rejects requests
      with malformed header names.

    Returns PASS if any smuggling prevention measure is found, FAIL
    otherwise.
    """
    evidence_parts: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.backends)
        + list(config.defaults)
    )

    # Check proxy sections for option httpclose and http-restrict-req-hdr-names
    for section in all_sections:
        section_name = getattr(section, "name", "unnamed") or "unnamed"
        for directive in section.get("option"):
            args_lower = directive.args.lower()
            if "httpclose" in args_lower:
                evidence_parts.append(
                    f"option httpclose in '{section_name}' "
                    f"(line {directive.line_number})"
                )
            if "http-restrict-req-hdr-names" in args_lower and "reject" in args_lower:
                evidence_parts.append(
                    f"option http-restrict-req-hdr-names reject in '{section_name}' "
                    f"(line {directive.line_number})"
                )

        # Check for http-request deny rules targeting duplicate headers
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" in args_lower:
                if "req.hdr_cnt(content-length)" in args_lower:
                    evidence_parts.append(
                        f"Duplicate Content-Length deny rule in '{section_name}': "
                        f"http-request {directive.args} (line {directive.line_number})"
                    )
                if "req.hdr_cnt(transfer-encoding)" in args_lower:
                    evidence_parts.append(
                        f"Duplicate Transfer-Encoding deny rule in '{section_name}': "
                        f"http-request {directive.args} (line {directive.line_number})"
                    )

    # Check global section for option http-use-htx
    for directive in config.global_section.get("option"):
        if "http-use-htx" in directive.args.lower():
            evidence_parts.append(
                f"option http-use-htx in global (line {directive.line_number})"
            )

    if evidence_parts:
        return Finding(
            check_id="HAPR-REQ-005",
            status=Status.PASS,
            message="HTTP request smuggling prevention measures are configured.",
            evidence="; ".join(evidence_parts),
        )

    return Finding(
        check_id="HAPR-REQ-005",
        status=Status.FAIL,
        message=(
            "No HTTP request smuggling prevention measures found. Consider "
            "adding 'option httpclose', 'option http-use-htx', or deny rules "
            "for duplicate Content-Length/Transfer-Encoding headers to mitigate "
            "HTTP request smuggling attacks."
        ),
        evidence=(
            "No option httpclose, option http-use-htx, duplicate header deny rules, "
            "or option http-restrict-req-hdr-names reject directives detected."
        ),
    )


# ---------------------------------------------------------------------------
# HAPR-H2-001  HTTP/2 stream limits
# ---------------------------------------------------------------------------

def _h2_in_use(config: HAProxyConfig) -> tuple[bool, list[str]]:
    """Return (True, evidence) if any bind line advertises HTTP/2."""
    h2_binds: list[str] = []
    for section in config.all_frontends_and_listens:
        section_name = getattr(section, "name", "unnamed") or "unnamed"
        for bind in section.binds:
            raw_lower = bind.raw.lower()
            if "alpn" in raw_lower and "h2" in raw_lower:
                h2_binds.append(f"[{section_name}] bind {bind.raw}")
            elif "proto h2" in raw_lower:
                h2_binds.append(f"[{section_name}] bind {bind.raw}")
    return bool(h2_binds), h2_binds


def check_h2_stream_limits(config: HAProxyConfig) -> Finding:
    """HAPR-H2-001: Check HTTP/2 stream limit configuration.

    When HTTP/2 is enabled, the ``tune.h2.max-concurrent-streams``
    directive should be set to limit the number of concurrent streams
    per connection.  Additionally, ``tune.h2.initial-window-size`` and
    ``tune.h2.max-frame-size`` provide further control over HTTP/2
    resource consumption.  Without these limits, a client can open
    many streams and exhaust server resources (Rapid Reset / CVE-2023-44487).

    Returns PASS if stream limits are configured, FAIL if HTTP/2 is in
    use but no stream limits are set, and N/A if HTTP/2 is not used.
    """
    h2_used, h2_evidence = _h2_in_use(config)

    if not h2_used:
        return Finding(
            check_id="HAPR-H2-001",
            status=Status.NOT_APPLICABLE,
            message="HTTP/2 is not advertised on any bind line; stream limit check is not applicable.",
            evidence="No bind lines with 'alpn h2' or 'proto h2' found.",
        )

    tuning_found: list[str] = []

    max_streams = config.global_section.get_value("tune.h2.max-concurrent-streams")
    if max_streams:
        tuning_found.append(f"tune.h2.max-concurrent-streams {max_streams}")

    initial_window = config.global_section.get_value("tune.h2.initial-window-size")
    if initial_window:
        tuning_found.append(f"tune.h2.initial-window-size {initial_window}")

    max_frame = config.global_section.get_value("tune.h2.max-frame-size")
    if max_frame:
        tuning_found.append(f"tune.h2.max-frame-size {max_frame}")

    if tuning_found:
        return Finding(
            check_id="HAPR-H2-001",
            status=Status.PASS,
            message="HTTP/2 stream limits are configured in the global section.",
            evidence="; ".join(tuning_found),
        )

    return Finding(
        check_id="HAPR-H2-001",
        status=Status.FAIL,
        message=(
            "HTTP/2 is enabled but no stream limits are configured. "
            "Set 'tune.h2.max-concurrent-streams' in the global section "
            "to limit concurrent streams per connection and mitigate "
            "HTTP/2 Rapid Reset attacks."
        ),
        evidence=f"H2 binds: {'; '.join(h2_evidence[:5])}; no tune.h2.* directives found.",
    )


# ---------------------------------------------------------------------------
# HAPR-H2-002  H2C smuggling prevention
# ---------------------------------------------------------------------------

def check_h2c_smuggling_prevention(config: HAProxyConfig) -> Finding:
    """HAPR-H2-002: Check for H2C (HTTP/2 cleartext) smuggling prevention.

    HTTP/2 cleartext (h2c) allows HTTP/2 without TLS.  When a non-SSL
    bind line advertises ``h2``, clients can initiate an HTTP/2
    connection over plaintext or request an upgrade via the ``Upgrade:
    h2c`` header.  This can be exploited for request smuggling if
    upstream servers interpret the upgrade differently.

    Mitigation is to either:
    * Only use ``h2`` over TLS (no non-SSL h2 binds), or
    * Add ``http-request deny`` rules targeting the ``Upgrade: h2c``
      header on non-SSL frontends.

    Returns PASS if all h2 binds are over SSL (no h2c exposure), PARTIAL
    if non-SSL h2 binds exist but deny rules for h2c upgrade are present,
    FAIL if non-SSL h2 binds exist without protection, and N/A if HTTP/2
    is not used at all.
    """
    h2_used, _ = _h2_in_use(config)

    if not h2_used:
        return Finding(
            check_id="HAPR-H2-002",
            status=Status.NOT_APPLICABLE,
            message="HTTP/2 is not advertised on any bind line; H2C smuggling check is not applicable.",
            evidence="No bind lines with 'alpn h2' or 'proto h2' found.",
        )

    # Find non-SSL bind lines that advertise h2 (these are h2c-capable)
    h2c_binds: list[str] = []
    h2c_sections: list = []

    for section in config.all_frontends_and_listens:
        section_name = getattr(section, "name", "unnamed") or "unnamed"
        for bind in section.binds:
            raw_lower = bind.raw.lower()
            has_h2 = ("alpn" in raw_lower and "h2" in raw_lower) or "proto h2" in raw_lower
            if has_h2 and not bind.ssl:
                h2c_binds.append(f"[{section_name}] bind {bind.raw}")
                if section not in h2c_sections:
                    h2c_sections.append(section)

    # If all h2 binds are over SSL, no h2c exposure
    if not h2c_binds:
        return Finding(
            check_id="HAPR-H2-002",
            status=Status.PASS,
            message="All HTTP/2 bind lines use SSL/TLS; no H2C (cleartext) exposure.",
            evidence="All h2 binds have SSL enabled.",
        )

    # Check if non-SSL h2 sections have deny rules for h2c upgrade
    has_deny_rule = False
    deny_evidence: list[str] = []

    for section in h2c_sections:
        section_name = getattr(section, "name", "unnamed") or "unnamed"
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" in args_lower and "upgrade" in args_lower and "h2c" in args_lower:
                has_deny_rule = True
                deny_evidence.append(
                    f"[{section_name}] http-request {directive.args}"
                )

    if has_deny_rule:
        return Finding(
            check_id="HAPR-H2-002",
            status=Status.PARTIAL,
            message=(
                "Non-SSL HTTP/2 (h2c) bind lines exist but deny rules for "
                "h2c upgrade are present. For full protection, consider "
                "using HTTP/2 only over TLS."
            ),
            evidence=(
                f"H2C binds: {'; '.join(h2c_binds[:3])}; "
                f"Deny rules: {'; '.join(deny_evidence[:3])}"
            ),
        )

    return Finding(
        check_id="HAPR-H2-002",
        status=Status.FAIL,
        message=(
            "Non-SSL HTTP/2 (h2c) bind lines are configured without "
            "smuggling prevention. Add 'http-request deny if "
            "{ req.hdr(upgrade) -i h2c }' or restrict HTTP/2 to TLS-only "
            "binds to prevent H2C request smuggling."
        ),
        evidence=f"Unprotected H2C binds: {'; '.join(h2c_binds[:5])}",
    )
