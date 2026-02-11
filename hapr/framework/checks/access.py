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

    for section in config.all_frontends_and_listens:
        section_label = section.name or "(unnamed)"

        # Check ACL args for admin path references
        for acl in section.acls:
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
        evidence="Searched all frontend and listen sections for admin path ACLs or deny rules.",
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
