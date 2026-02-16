"""Access control checks for HAProxy configurations.

Examines ACL definitions, admin path restrictions, rate limiting,
stick-table usage, stats endpoint security, and userlist password storage.
"""

from __future__ import annotations

import re

from ...models import HAProxyConfig, Finding, Status

# Crypt-style hash prefix ($id$...) — covers MD5 ($1$), Blowfish ($2a$/$2b$/$2y$),
# SHA-256 ($5$), SHA-512 ($6$), and similar schemes.
_CRYPT_HASH_RE = re.compile(r"^\$\d\w?\$")

# Common weak passwords that should be flagged in stats auth
_WEAK_PASSWORDS = {
    "admin", "password", "123456", "haproxy", "changeme", "default",
    "pass", "test", "1234", "12345678", "root", "secret", "abc123",
    "letmein", "welcome", "monkey", "master", "qwerty",
}


def check_acls_defined(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-001: Check per-frontend/listen ACL coverage.

    ACLs are the primary mechanism in HAProxy for making routing and access
    decisions.  This check validates that every frontend and listen section
    has at least one ACL directive defined.

    Returns N/A if there are no frontends or listens.
    Returns PASS if ALL frontends/listens have ACLs.
    Returns PARTIAL if SOME (but not all) frontends/listens have ACLs.
    Returns FAIL if NO frontends/listens have ACLs.
    """
    all_sections = config.all_frontends_and_listens

    if not all_sections:
        return Finding(
            check_id="HAPR-ACL-001",
            status=Status.NOT_APPLICABLE,
            message="No frontend or listen sections found in the configuration.",
            evidence="No frontend or listen sections to evaluate.",
        )

    sections_with_acls: list[str] = []
    sections_without_acls: list[str] = []

    for section in all_sections:
        label = section.name or "(unnamed)"
        if section.acls:
            sections_with_acls.append(label)
        else:
            sections_without_acls.append(label)

    total = len(all_sections)
    with_acls = len(sections_with_acls)

    if with_acls == total:
        return Finding(
            check_id="HAPR-ACL-001",
            status=Status.PASS,
            message="All frontends/listens have ACL directives defined.",
            evidence=f"Sections with ACLs: {', '.join(sections_with_acls)}",
        )

    if with_acls > 0:
        return Finding(
            check_id="HAPR-ACL-001",
            status=Status.PARTIAL,
            message=(
                f"Only {with_acls}/{total} frontends/listens have ACL directives. "
                "All frontends should define ACLs for proper access control."
            ),
            evidence=(
                f"With ACLs: {', '.join(sections_with_acls)}; "
                f"Missing ACLs: {', '.join(sections_without_acls)}"
            ),
        )

    return Finding(
        check_id="HAPR-ACL-001",
        status=Status.FAIL,
        message="No ACL directives found in any frontend or listen section.",
        evidence=f"Missing ACLs: {', '.join(sections_without_acls)}",
    )


def check_admin_path_restricted(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-002: Check for restrictions on common admin paths.

    Looks for ACL rules or ``http-request deny`` directives that reference
    well-known administrative paths such as ``/admin``, ``/manager``,
    ``/console``, ``/wp-admin``, ``/phpmyadmin``, and similar.

    Returns PASS if at least one such restriction is detected.
    Returns FAIL if no admin path protection is found.
    """
    admin_patterns = [
        r"/admin",
        r"/manager",
        r"/console",
        r"/wp-admin",
        r"/phpmyadmin",
        r"/wp-login",
        r"/cgi-bin",
        r"/actuator",
        r"/solr",
    ]
    # Build a single regex that matches any of the admin path fragments
    combined_re = re.compile(
        "|".join(re.escape(p) for p in admin_patterns), re.IGNORECASE
    )

    evidence_lines: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.backends)
    )

    for section in all_sections:
        section_label = section.name or "(unnamed)"

        # Check ACL args for admin path references
        for acl in section.get("acl"):
            if combined_re.search(acl.args):
                evidence_lines.append(
                    f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                )

        # Check http-request deny rules for admin path references
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" in args_lower and combined_re.search(directive.args):
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-ACL-002",
            status=Status.PASS,
            message="Admin path restrictions detected in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-ACL-002",
        status=Status.FAIL,
        message=(
            "No restrictions on common admin paths detected. "
            "Paths like /admin, /manager, /wp-admin, and /phpmyadmin "
            "should be restricted or denied."
        ),
        evidence="Searched all frontend, listen, and backend sections for admin path ACLs or deny rules.",
    )


def check_rate_limiting(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-003: Check for rate-limiting mechanisms.

    Looks for evidence of rate limiting via:
    - ``stick-table`` directives combined with ``http-request track-sc`` or
      ``tcp-request content track-sc``
    - ``http-request deny`` rules referencing ``sc_`` sample fetches
      (e.g. ``sc_http_req_rate``, ``sc0_get_gpc0``)

    Returns PASS if rate limiting is detected, FAIL otherwise.
    """
    evidence_lines: list[str] = []

    all_sections = (
        list(config.frontends)
        + list(config.backends)
        + list(config.listens)
    )

    for section in all_sections:
        section_label = section.name or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # http-request track-sc0/1/2 ...
            if keyword == "http-request" and "track-sc" in args_lower:
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

            # tcp-request content track-sc0/1/2 ...
            if keyword == "tcp-request" and "track-sc" in args_lower:
                evidence_lines.append(
                    f"[{section_label}] tcp-request {directive.args} (line {directive.line_number})"
                )

            # http-request deny ... sc_ condition (rate-limit enforcement)
            if keyword == "http-request" and "deny" in args_lower and "sc_" in args_lower:
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-ACL-003",
            status=Status.PASS,
            message="Rate limiting directives detected in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-ACL-003",
        status=Status.FAIL,
        message=(
            "No rate limiting detected. Consider using stick-tables with "
            "http-request track-sc and deny rules to limit abusive traffic."
        ),
        evidence="Searched all sections for track-sc and sc_ deny rules; none found.",
    )


def check_stick_tables(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-004: Check for stick-table directives.

    Stick-tables provide in-memory tracking for connection rates, error rates,
    and session persistence.  They are a prerequisite for rate limiting and
    abuse detection.

    Returns PASS if at least one ``stick-table`` directive is found in any
    frontend, backend, or listen section.  Returns FAIL if none are found.
    """
    evidence_lines: list[str] = []

    all_sections = (
        list(config.frontends)
        + list(config.backends)
        + list(config.listens)
    )

    for section in all_sections:
        section_label = section.name or "(unnamed)"
        for directive in section.get("stick-table"):
            evidence_lines.append(
                f"[{section_label}] stick-table {directive.args} (line {directive.line_number})"
            )

    if evidence_lines:
        return Finding(
            check_id="HAPR-ACL-004",
            status=Status.PASS,
            message="Stick-table directives found in the configuration.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-ACL-004",
        status=Status.FAIL,
        message=(
            "No stick-table directives found. Stick-tables are required for "
            "connection tracking, rate limiting, and abuse detection."
        ),
        evidence="Searched all frontend, backend, and listen sections; no stick-table directives found.",
    )


def check_stats_access_restricted(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-005: Check that the stats endpoint is secured if enabled.

    If stats is enabled (via ``stats enable`` or ``stats uri`` in any section),
    verifies that ``stats auth`` or ACL-based access control is also configured
    for the same section.  Also checks for ``stats hide-version`` (to prevent
    version disclosure) and ``stats admin if`` ACL restriction (to limit admin
    access).

    Returns PASS if stats is not enabled, OR if stats has auth + hide-version
    + admin ACL restriction.
    Returns PARTIAL if stats has auth but is missing hide-version or admin ACL.
    Returns FAIL if stats is enabled without authentication.
    """
    stats_enabled_sections: list[str] = []
    secured_sections: list[str] = []
    unsecured_sections: list[str] = []
    weak_password_issues: list[str] = []
    missing_hardening: list[str] = []

    # Track global hide-version and admin ACL across all sections
    global_has_hide_version = False
    global_has_admin_acl = False

    # Check all sections that can carry stats directives
    all_sections = (
        list(config.frontends)
        + list(config.backends)
        + list(config.listens)
        + list(config.defaults)
    )

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        has_stats_enable = False
        has_stats_uri = False
        has_stats_auth = False
        has_acl_restriction = False
        has_hide_version = False
        has_admin_acl = False

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            if keyword == "stats" and args_lower.startswith("enable"):
                has_stats_enable = True
            elif keyword == "stats" and args_lower.startswith("uri"):
                has_stats_uri = True
            elif keyword == "stats" and args_lower.startswith("auth"):
                has_stats_auth = True
                # Validate password strength: "auth user:password"
                auth_value = directive.args[len("auth"):].strip()
                if ":" in auth_value:
                    username, password = auth_value.split(":", 1)
                    if len(password) < 8:
                        weak_password_issues.append(
                            f"[{section_label}] stats auth password too short ({len(password)} chars)"
                        )
                    if password.lower() in _WEAK_PASSWORDS:
                        weak_password_issues.append(
                            f"[{section_label}] stats auth uses common weak password"
                        )
                    if username == password:
                        weak_password_issues.append(
                            f"[{section_label}] stats auth username equals password"
                        )
            elif keyword == "stats" and args_lower.startswith("hide-version"):
                has_hide_version = True
                global_has_hide_version = True
            elif keyword == "stats" and args_lower.startswith("admin"):
                has_admin_acl = True
                global_has_admin_acl = True

            # Check for ACL-based http-request deny/allow near stats
            if keyword == "http-request" and "stats" in args_lower:
                has_acl_restriction = True

        stats_enabled = has_stats_enable or has_stats_uri
        if stats_enabled:
            stats_enabled_sections.append(section_label)
            if has_stats_auth or has_acl_restriction:
                secured_sections.append(section_label)
            else:
                unsecured_sections.append(section_label)

    if not stats_enabled_sections:
        return Finding(
            check_id="HAPR-ACL-005",
            status=Status.PASS,
            message="Stats endpoint is not enabled; no access control required.",
            evidence="No 'stats enable' or 'stats uri' directives found in any section.",
        )

    if unsecured_sections:
        return Finding(
            check_id="HAPR-ACL-005",
            status=Status.FAIL,
            message=(
                "Stats endpoint is enabled without authentication in one or more sections. "
                "Add 'stats auth <user>:<password>' or ACL-based restrictions."
            ),
            evidence=f"Unsecured stats sections: {', '.join(unsecured_sections)}",
        )

    if weak_password_issues:
        return Finding(
            check_id="HAPR-ACL-005",
            status=Status.PARTIAL,
            message=(
                "Stats endpoint is secured with authentication but the password is weak. "
                "Use a strong password (8+ characters, not a common word)."
            ),
            evidence="; ".join(weak_password_issues),
        )

    # Auth is present and password is strong — now check for hardening (hide-version, admin ACL)
    if not global_has_hide_version:
        missing_hardening.append("stats hide-version")
    if not global_has_admin_acl:
        missing_hardening.append("stats admin if <acl> (admin ACL restriction)")

    if missing_hardening:
        return Finding(
            check_id="HAPR-ACL-005",
            status=Status.PARTIAL,
            message=(
                "Stats endpoint has authentication but is missing additional "
                f"protections: {', '.join(missing_hardening)}."
            ),
            evidence=f"Secured sections: {', '.join(secured_sections)}; missing: {', '.join(missing_hardening)}",
        )

    return Finding(
        check_id="HAPR-ACL-005",
        status=Status.PASS,
        message="Stats endpoint is enabled and fully secured with authentication, version hiding, and admin ACL.",
        evidence=f"Secured stats sections: {', '.join(secured_sections)}",
    )


def check_userlist_passwords(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-006: Check that userlist passwords use hashed storage.

    HAProxy supports two password directives in userlists:
    - ``password`` — should contain a crypt(3)-style hash (e.g. ``$6$...``)
    - ``insecure-password`` — stores the password in cleartext

    Returns N/A if no userlists are defined, FAIL if any user has
    ``insecure-password`` or a ``password`` value that doesn't look like
    a crypt hash, PASS if all passwords are properly hashed.
    """
    if not config.userlists:
        return Finding(
            check_id="HAPR-ACL-006",
            status=Status.NOT_APPLICABLE,
            message="No userlists defined in the configuration.",
            evidence="No 'userlist' sections found.",
        )

    issues: list[str] = []

    for ul in config.userlists:
        ul_label = ul.name or "(unnamed)"
        for user in ul.users:
            if user.password_type == "insecure-password":
                issues.append(
                    f"[{ul_label}] user '{user.name}' uses insecure-password "
                    f"(cleartext) on line {user.line_number}"
                )
            elif user.password_type == "password":
                if not _CRYPT_HASH_RE.match(user.password_value):
                    issues.append(
                        f"[{ul_label}] user '{user.name}' has password value "
                        f"that does not match crypt hash format on line {user.line_number}"
                    )

    if issues:
        return Finding(
            check_id="HAPR-ACL-006",
            status=Status.FAIL,
            message=(
                "One or more userlist passwords are stored insecurely. "
                "Use 'password' with a crypt(3) hash (e.g. SHA-512 via mkpasswd) "
                "instead of 'insecure-password'."
            ),
            evidence="; ".join(issues),
        )

    return Finding(
        check_id="HAPR-ACL-006",
        status=Status.PASS,
        message="All userlist passwords use hashed storage.",
        evidence=f"Checked {sum(len(ul.users) for ul in config.userlists)} user(s) across {len(config.userlists)} userlist(s).",
    )


def check_source_ip_restrictions(config: HAProxyConfig) -> Finding:
    """HAPR-ACL-007: Check for source IP restrictions on admin interfaces.

    Admin interfaces (stats pages, management endpoints) should be restricted
    to trusted source IP ranges using ``src``-based ACLs combined with
    ``http-request deny`` or ``http-request allow`` rules.

    Searches all frontends and listen sections for:

    1. ACLs that use ``src`` in their arguments (e.g. ``acl trusted_src src 10.0.0.0/8``).
    2. ``http-request deny`` or ``http-request allow`` rules that reference
       ``src``-based ACLs or use inline ``src`` conditions.

    Returns
    -------
    Finding
        PASS -- Source IP restrictions are found in at least one section.
        FAIL -- No source IP restrictions found.
    """
    evidence_lines: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.backends)
    )

    for section in all_sections:
        section_label = section.name or "(unnamed)"

        # Collect names of src-based ACLs for cross-referencing
        src_acl_names: list[str] = []

        # 1. Check ACLs for 'src' usage
        for acl in section.get("acl"):
            # ACL args format: "<name> <criterion> <values>"
            # e.g. "trusted_src src 10.0.0.0/8"
            acl_tokens = acl.args.split()
            if len(acl_tokens) >= 2 and acl_tokens[1].lower() == "src":
                src_acl_names.append(acl_tokens[0])
                evidence_lines.append(
                    f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                )

        # 2. Check http-request deny/allow rules referencing src-based ACLs
        #    or using inline src conditions
        for directive in section.get("http-request"):
            args_lower = directive.args.lower()
            if "deny" not in args_lower and "allow" not in args_lower:
                continue

            # Check for inline src reference in the rule
            has_src_ref = False
            if re.search(r"\bsrc\b", args_lower):
                has_src_ref = True

            # Check if the rule references any src-based ACL by name
            if not has_src_ref:
                for acl_name in src_acl_names:
                    if acl_name.lower() in args_lower:
                        has_src_ref = True
                        break

            if has_src_ref:
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-ACL-007",
            status=Status.PASS,
            message="Source IP restrictions are configured for access control.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-ACL-007",
        status=Status.FAIL,
        message=(
            "No source IP restrictions found on admin interfaces. "
            "Add 'src'-based ACLs and corresponding 'http-request deny' rules "
            "to restrict access to stats pages and management endpoints to "
            "trusted IP ranges."
        ),
        evidence="Searched all frontend, listen, and backend sections for src-based ACLs and deny/allow rules; none found.",
    )


def check_jwt_verification(config: HAProxyConfig) -> Finding:
    """HAPR-JWT-001: Check if JWT signature verification is enforced.

    HAProxy 2.5+ supports native JWT verification, and earlier versions can
    use Lua scripts.  This check looks for evidence that JWT tokens are
    verified before being trusted.

    Searches for:
    - ``http-request deny unless`` patterns combined with Authorization header
      and JWT verification references
    - ``http-request set-var`` with ``req.hdr(Authorization)`` and jwt_verify
    - Any directive containing the keyword ``jwt`` (case-insensitive)
    - Lua-based JWT handlers (``http-request lua.`` with jwt reference)

    Returns PASS if JWT verification is found, FAIL if JWT-related patterns
    are present without verification, N/A if no JWT patterns exist at all.
    """
    jwt_evidence: list[str] = []
    jwt_related: bool = False

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.defaults)
    )

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()
            full_lower = f"{keyword} {args_lower}"

            # Detect any JWT-related configuration
            if "jwt" in full_lower:
                jwt_related = True

                # Native JWT verification patterns
                if "jwt_verify" in args_lower or "jwt-verify" in args_lower:
                    jwt_evidence.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

                # Lua-based JWT verification
                if keyword == "http-request" and "lua." in args_lower and "jwt" in args_lower:
                    jwt_evidence.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

                # http-request deny with Authorization header + jwt
                if keyword == "http-request" and "deny" in args_lower and "authorization" in args_lower:
                    jwt_evidence.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

                # set-var with jwt reference
                if keyword == "http-request" and "set-var" in args_lower and "jwt" in args_lower:
                    jwt_evidence.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

        # Also check ACLs in sections that have them
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                if "jwt" in acl_lower:
                    jwt_related = True
                    jwt_evidence.append(
                        f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                    )

    if not jwt_related:
        return Finding(
            check_id="HAPR-JWT-001",
            status=Status.NOT_APPLICABLE,
            message="No JWT-related configuration found.",
            evidence="No directives or ACLs referencing JWT were found in any section.",
        )

    if jwt_evidence:
        return Finding(
            check_id="HAPR-JWT-001",
            status=Status.PASS,
            message="JWT signature verification is configured.",
            evidence="\n".join(jwt_evidence),
        )

    return Finding(
        check_id="HAPR-JWT-001",
        status=Status.FAIL,
        message=(
            "JWT-related configuration found but no signature verification detected. "
            "Ensure JWT tokens are verified using jwt_verify, Lua JWT libraries, "
            "or deny rules that enforce Authorization header validation."
        ),
        evidence="JWT references found but no verification directives detected.",
    )


def check_jwt_algorithm_restriction(config: HAProxyConfig) -> Finding:
    """HAPR-JWT-002: Check that JWT 'alg:none' attack is prevented.

    The JWT ``alg:none`` attack allows attackers to bypass signature
    verification by setting the algorithm to ``none``.  This check looks
    for configuration that restricts allowed JWT algorithms.

    Searches for:
    - JWT verification directives that specify allowed algorithms
    - ACLs or variables referencing JWT verification with algorithm constraints
    - Deny rules that block unsigned or algorithm-unspecified JWTs

    Returns PASS if algorithm restrictions are found, FAIL if JWT is used
    without algorithm restrictions, N/A if no JWT configuration exists.
    """
    jwt_found: bool = False
    algo_restriction_evidence: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.defaults)
    )

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()
            full_lower = f"{keyword} {args_lower}"

            if "jwt" not in full_lower:
                continue

            jwt_found = True

            # Look for algorithm specification in JWT verification directives
            # Common patterns: jwt_verify with algorithm param, alg restriction
            has_algo = False
            for algo_kw in ("alg", "algorithm", "rs256", "rs384", "rs512",
                            "es256", "es384", "es512", "hs256", "hs384",
                            "hs512", "ps256", "ps384", "ps512", "eddsa"):
                if algo_kw in args_lower:
                    has_algo = True
                    break

            if has_algo:
                algo_restriction_evidence.append(
                    f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                )

            # Deny rules that block "none" algorithm or unsigned tokens
            if keyword == "http-request" and "deny" in args_lower:
                if "none" in args_lower or "unsigned" in args_lower:
                    algo_restriction_evidence.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

        # Check ACLs for algorithm restrictions
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                if "jwt" in acl_lower:
                    jwt_found = True
                    for algo_kw in ("alg", "algorithm", "rs256", "rs384", "rs512",
                                    "es256", "es384", "es512", "hs256", "hs384",
                                    "hs512", "none"):
                        if algo_kw in acl_lower:
                            algo_restriction_evidence.append(
                                f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                            )
                            break

    if not jwt_found:
        return Finding(
            check_id="HAPR-JWT-002",
            status=Status.NOT_APPLICABLE,
            message="No JWT configuration found.",
            evidence="No directives or ACLs referencing JWT were found in any section.",
        )

    if algo_restriction_evidence:
        return Finding(
            check_id="HAPR-JWT-002",
            status=Status.PASS,
            message="JWT algorithm restrictions are configured, mitigating the alg:none attack.",
            evidence="\n".join(algo_restriction_evidence),
        )

    return Finding(
        check_id="HAPR-JWT-002",
        status=Status.FAIL,
        message=(
            "JWT configuration found but no algorithm restrictions detected. "
            "Without explicit algorithm restrictions, the configuration may be "
            "vulnerable to the JWT alg:none attack. Specify allowed algorithms "
            "in the JWT verification directive."
        ),
        evidence="JWT references found but no algorithm restriction directives detected.",
    )


def check_bot_detection(config: HAProxyConfig) -> Finding:
    """HAPR-BOT-001: Check if bot detection patterns are configured.

    Looks for User-Agent based filtering via ACLs or http-request rules
    that reference known bot patterns (bot, crawler, spider, etc.), as well
    as rate limiting rules specific to user-agent classification.

    Searches frontends, listens, and defaults for:
    - ACLs referencing ``req.hdr(User-Agent)`` or ``hdr(User-Agent)``
    - ``http-request deny`` rules targeting user-agent patterns
    - Rate limiting or tracking rules tied to user-agent classification

    Returns PASS if bot detection is configured, FAIL if not.
    """
    evidence_lines: list[str] = []

    all_sections = (
        list(config.all_frontends_and_listens)
        + list(config.defaults)
    )

    # Patterns that indicate bot detection
    bot_keywords = ("bot", "crawler", "spider", "scraper", "wget", "curl",
                    "httpclient", "python-requests", "go-http", "user-agent",
                    "user_agent")

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        # Check ACLs for user-agent based bot filtering
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                if "hdr(user-agent)" in acl_lower or "req.hdr(user-agent)" in acl_lower:
                    evidence_lines.append(
                        f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                    )
                elif any(kw in acl_lower for kw in bot_keywords):
                    # ACL might reference bot-related names or patterns
                    if "hdr" in acl_lower or "user" in acl_lower:
                        evidence_lines.append(
                            f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                        )

        # Check directives for user-agent filtering rules
        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            if keyword != "http-request":
                continue

            # http-request deny rules referencing user-agent
            if "deny" in args_lower and (
                "hdr(user-agent)" in args_lower
                or "req.hdr(user-agent)" in args_lower
            ):
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )
            # http-request deny referencing bot-named ACLs
            elif "deny" in args_lower and any(kw in args_lower for kw in ("bot", "crawler", "spider")):
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )
            # Track-sc rules for user-agent based rate limiting
            elif "track-sc" in args_lower and "hdr(user-agent)" in args_lower:
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

    if evidence_lines:
        return Finding(
            check_id="HAPR-BOT-001",
            status=Status.PASS,
            message="Bot detection patterns are configured.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-BOT-001",
        status=Status.FAIL,
        message=(
            "No bot detection patterns found. Consider adding User-Agent based "
            "ACLs to identify and block known malicious bots, crawlers, and "
            "scrapers (e.g. 'acl bad_bot hdr(User-Agent) -i -m sub bot crawler spider')."
        ),
        evidence="Searched all frontend, listen, and defaults sections for User-Agent filtering rules; none found.",
    )


def check_ip_reputation_integration(config: HAProxyConfig) -> Finding:
    """HAPR-IPREP-001: Check if IP reputation / threat intelligence is integrated.

    Looks for evidence of CrowdSec bouncer, fail2ban integration, IP
    reputation map files, stick-table GPC-based reputation scoring, or
    ACL rules referencing external IP block-/deny-lists.

    Searches all frontends, listens, backends, and defaults for:
    - Directives containing "crowdsec", "fail2ban", "ip-reputation",
      "blocklist", "blacklist", or "denylist"
    - ``map(`` or ``map_ip`` patterns combined with deny rules
    - Stick-table ``gpc`` (general purpose counter) patterns suggesting
      reputation scoring
    - ACLs referencing external IP lists

    Returns PASS if integration is detected, FAIL if not.
    """
    evidence_lines: list[str] = []

    reputation_keywords = (
        "crowdsec", "fail2ban", "ip-reputation", "ip_reputation",
        "blocklist", "blacklist", "denylist", "deny-list",
        "block-list", "black-list", "ipreputation", "threat-intel",
        "threat_intel",
    )

    all_sections = (
        list(config.frontends)
        + list(config.backends)
        + list(config.listens)
        + list(config.defaults)
    )

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()
            full_lower = f"{keyword} {args_lower}"

            # Check for reputation-related keywords
            for rep_kw in reputation_keywords:
                if rep_kw in full_lower:
                    evidence_lines.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )
                    break

            # Check for map file patterns used with deny rules
            if keyword == "http-request" and "deny" in args_lower:
                if "map(" in args_lower or "map_ip(" in args_lower:
                    evidence_lines.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

            # Check for GPC-based reputation scoring — only count as IP
            # reputation when combined with source-IP deny/reject rules,
            # not generic GPC usage like circuit breakers.
            if "gpc" in args_lower and keyword in ("http-request", "tcp-request"):
                if ("deny" in args_lower or "reject" in args_lower or "tarpit" in args_lower) and "src" in args_lower:
                    evidence_lines.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

        # Check ACLs for external IP list references
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                for rep_kw in reputation_keywords:
                    if rep_kw in acl_lower:
                        evidence_lines.append(
                            f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                        )
                        break
                # Map file references in ACLs
                if "map(" in acl_lower or "map_ip(" in acl_lower:
                    evidence_lines.append(
                        f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                    )

    # Deduplicate evidence while preserving order
    seen: set[str] = set()
    unique_evidence: list[str] = []
    for line in evidence_lines:
        if line not in seen:
            seen.add(line)
            unique_evidence.append(line)

    if unique_evidence:
        return Finding(
            check_id="HAPR-IPREP-001",
            status=Status.PASS,
            message="IP reputation or threat intelligence integration detected.",
            evidence="\n".join(unique_evidence),
        )

    return Finding(
        check_id="HAPR-IPREP-001",
        status=Status.FAIL,
        message=(
            "No IP reputation or threat intelligence integration detected. "
            "Consider integrating CrowdSec, fail2ban, or external IP "
            "blocklists via map files to block known malicious sources."
        ),
        evidence=(
            "Searched all sections for reputation keywords, map-based deny "
            "rules, and GPC counters; none found."
        ),
    )


def check_api_authentication(config: HAProxyConfig) -> Finding:
    """HAPR-API-001: Check if API authentication enforcement is configured.

    Looks for patterns that enforce authentication on API endpoints:
    - ACLs matching API paths (``path_beg /api``, ``path_beg /v1``, etc.)
    - Combined with auth checks (Authorization header validation,
      ``http-request deny`` if no auth header, ``http-request auth``)

    Returns PASS if API auth is found, FAIL if API paths exist without auth,
    N/A if no API path patterns are detected.
    """
    api_path_patterns = ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest")

    api_sections: list[str] = []
    auth_sections: list[str] = []
    evidence_lines: list[str] = []

    all_sections = list(config.all_frontends_and_listens)

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        has_api_path = False
        has_auth = False

        # Check ACLs for API path references
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                if any(p in acl_lower for p in api_path_patterns):
                    has_api_path = True
                # Check for authorization header ACLs
                if "authorization" in acl_lower and "hdr" in acl_lower:
                    has_auth = True
                    evidence_lines.append(
                        f"[{section_label}] acl {acl.args} (line {acl.line_number})"
                    )

        # Check directives for API-related auth enforcement
        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # Detect API path references in directives
            if any(p in args_lower for p in api_path_patterns):
                has_api_path = True

            # http-request auth (basic auth enforcement)
            if keyword == "http-request" and args_lower.strip().startswith("auth"):
                has_auth = True
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

            # http-request deny unless Authorization header
            if keyword == "http-request" and "deny" in args_lower and "authorization" in args_lower:
                has_auth = True
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

            # http-request deny referencing auth-related ACLs
            if keyword == "http-request" and "deny" in args_lower and (
                "authenticated" in args_lower
                or "auth" in args_lower.split()
                or "no_auth" in args_lower
                or "no-auth" in args_lower
            ):
                has_auth = True
                evidence_lines.append(
                    f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                )

        if has_api_path:
            api_sections.append(section_label)
        if has_api_path and has_auth:
            auth_sections.append(section_label)

    if not api_sections:
        return Finding(
            check_id="HAPR-API-001",
            status=Status.NOT_APPLICABLE,
            message="No API path patterns found in the configuration.",
            evidence="No ACLs or directives referencing /api, /v1, /v2, /graphql, or /rest paths were found.",
        )

    if auth_sections:
        return Finding(
            check_id="HAPR-API-001",
            status=Status.PASS,
            message="API authentication enforcement is configured.",
            evidence="\n".join(evidence_lines),
        )

    return Finding(
        check_id="HAPR-API-001",
        status=Status.FAIL,
        message=(
            "API path patterns found but no authentication enforcement detected. "
            "Add 'http-request deny' rules that enforce Authorization header "
            "presence or use 'http-request auth' for API endpoints."
        ),
        evidence=f"API paths found in sections: {', '.join(api_sections)}; no auth rules detected.",
    )


def check_api_rate_limiting(config: HAProxyConfig) -> Finding:
    """HAPR-API-002: Check if per-API rate limiting is configured.

    Looks for stick-tables or rate limiting rules specific to API paths:
    - API path ACLs combined with stick-table tracking
    - ``http-request track-sc`` combined with API path conditions
    - ``http-request deny`` rules combining API paths with rate counters

    Returns PASS if API-specific rate limiting is found, FAIL if API paths
    exist without rate limits, N/A if no API patterns are detected.
    """
    api_path_patterns = ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest")

    api_sections: list[str] = []
    rate_limited_sections: list[str] = []
    evidence_lines: list[str] = []

    all_sections = list(config.all_frontends_and_listens)

    for section in all_sections:
        section_label = getattr(section, "name", "") or "(unnamed)"

        has_api_path = False
        has_rate_limit = False

        # Track ACL names that reference API paths for cross-referencing
        api_acl_names: list[str] = []

        # Check ACLs for API path references
        if hasattr(section, "acls"):
            for acl in section.acls:
                acl_lower = acl.args.lower()
                if any(p in acl_lower for p in api_path_patterns):
                    has_api_path = True
                    # Extract ACL name (first token in args)
                    acl_tokens = acl.args.split()
                    if acl_tokens:
                        api_acl_names.append(acl_tokens[0].lower())

        # Check directives for API rate limiting patterns
        for directive in section.directives:
            keyword = directive.keyword.lower()
            args_lower = directive.args.lower()

            # Detect API path references in directives
            if any(p in args_lower for p in api_path_patterns):
                has_api_path = True

            # http-request track-sc with API path conditions
            if keyword == "http-request" and "track-sc" in args_lower:
                # Check if this track-sc references an API path ACL or API path directly
                if any(p in args_lower for p in api_path_patterns):
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                    )
                elif any(acl_name in args_lower for acl_name in api_acl_names):
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                    )

            # http-request deny rules combining API paths with rate counters (sc_)
            if keyword == "http-request" and "deny" in args_lower and "sc_" in args_lower:
                if any(p in args_lower for p in api_path_patterns):
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                    )
                elif any(acl_name in args_lower for acl_name in api_acl_names):
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] http-request {directive.args} (line {directive.line_number})"
                    )

            # tcp-request with track-sc and API context
            if keyword == "tcp-request" and "track-sc" in args_lower:
                if any(p in args_lower for p in api_path_patterns):
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] tcp-request {directive.args} (line {directive.line_number})"
                    )

        # Check for stick-table in the section (indicates rate tracking infrastructure)
        has_stick_table = bool(section.get("stick-table"))

        # If the section has API paths + stick-table + track-sc, it counts
        if has_api_path and has_stick_table:
            for directive in section.directives:
                keyword = directive.keyword.lower()
                args_lower = directive.args.lower()
                if keyword in ("http-request", "tcp-request") and "track-sc" in args_lower:
                    has_rate_limit = True
                    evidence_lines.append(
                        f"[{section_label}] {keyword} {directive.args} (line {directive.line_number})"
                    )

        if has_api_path:
            api_sections.append(section_label)
        if has_api_path and has_rate_limit:
            rate_limited_sections.append(section_label)

    if not api_sections:
        return Finding(
            check_id="HAPR-API-002",
            status=Status.NOT_APPLICABLE,
            message="No API path patterns found in the configuration.",
            evidence="No ACLs or directives referencing /api, /v1, /v2, /graphql, or /rest paths were found.",
        )

    # Deduplicate evidence while preserving order
    seen: set[str] = set()
    unique_evidence: list[str] = []
    for line in evidence_lines:
        if line not in seen:
            seen.add(line)
            unique_evidence.append(line)

    if rate_limited_sections:
        return Finding(
            check_id="HAPR-API-002",
            status=Status.PASS,
            message="API-specific rate limiting is configured.",
            evidence="\n".join(unique_evidence),
        )

    return Finding(
        check_id="HAPR-API-002",
        status=Status.FAIL,
        message=(
            "API path patterns found but no API-specific rate limiting detected. "
            "Add stick-tables with 'http-request track-sc' and 'http-request deny' "
            "rules tied to API path ACLs to limit abuse on API endpoints."
        ),
        evidence=f"API paths found in sections: {', '.join(api_sections)}; no rate limiting rules detected.",
    )
