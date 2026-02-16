"""TLS/SSL configuration checks for parsed HAProxy config.

These checks examine the static HAProxy configuration for TLS-related
security settings.  They do NOT perform live scanning --- see ``tls_live``
for runtime probes.
"""

from __future__ import annotations

import re

from ...models import Finding, HAProxyConfig, Severity, Status

# Versions considered weak (SSLv3, TLS 1.0, TLS 1.1)
_WEAK_VERSIONS = {"sslv3", "tlsv1.0", "tlsv10", "tlsv1.1", "tlsv11"}

# Versions considered acceptable (TLS 1.2+)
_STRONG_VERSIONS = {"tlsv1.2", "tlsv12", "tlsv1.3", "tlsv13"}

# Keywords that identify known-weak cipher components
_WEAK_CIPHER_KEYWORDS = {
    "DES", "3DES", "RC4", "MD5", "NULL", "EXPORT",
    "ANULL", "ENULL", "LOW", "DES-CBC3", "DES-CBC",
    "RC2", "SEED", "IDEA", "CAMELLIA128", "AECDH", "ADH",
}


def _find_weak_ciphers(cipher_string: str) -> list[str]:
    """Split a cipher string on ``:``, return individual ciphers that are weak.

    Ciphers prefixed with ``!`` are exclusions and are skipped.
    """
    weak: list[str] = []
    for cipher in cipher_string.split(":"):
        c = cipher.strip()
        if not c or c.startswith("!"):
            continue
        c_upper = c.upper()
        for keyword in _WEAK_CIPHER_KEYWORDS:
            if keyword in c_upper:
                weak.append(c)
                break
    return weak


# ---------------------------------------------------------------------------
# HAPR-TLS-001  Minimum TLS version
# ---------------------------------------------------------------------------

def check_min_tls_version(config: HAProxyConfig) -> Finding:
    """Check that the minimum TLS version is 1.2 or higher.

    Inspects:
      - ``ssl-default-bind-options`` in the global section for ``ssl-min-ver``
        and for explicit references to weak protocol versions.
      - Individual ``bind`` lines for ``ssl-min-ver`` options and weak version
        tokens (``sslv3``, ``tlsv10``, ``tlsv11``).

    Returns PASS if all enforce TLS 1.2+, PARTIAL if some do, FAIL if none do
    or weak versions are explicitly found.
    """
    g = config.global_section

    weak_found: list[str] = []
    strong_global = False
    strong_binds: list[str] = []
    weak_binds: list[str] = []

    # --- Check global ssl-default-bind-options ---
    bind_opts_directives = g.get("ssl-default-bind-options")
    for d in bind_opts_directives:
        tokens = d.args.lower().split()
        # Look for explicit weak version tokens
        for tok in tokens:
            if tok in _WEAK_VERSIONS or tok.lstrip("no-") in _WEAK_VERSIONS:
                # "no-sslv3" is fine -- it disables the weak version.
                if tok.startswith("no-"):
                    continue
                weak_found.append(f"global ssl-default-bind-options: {tok}")

        # Look for ssl-min-ver
        for i, tok in enumerate(tokens):
            if tok == "ssl-min-ver" and i + 1 < len(tokens):
                ver = tokens[i + 1]
                if ver in _STRONG_VERSIONS:
                    strong_global = True
                else:
                    weak_found.append(
                        f"global ssl-default-bind-options ssl-min-ver {ver}"
                    )

    # --- Check individual bind lines ---
    for bind in config.all_binds:
        if not bind.ssl:
            continue
        opts_lower = {k.lower(): v.lower() for k, v in bind.options.items()}

        # Check ssl-min-ver on the bind line
        min_ver = opts_lower.get("ssl-min-ver", "")
        if min_ver:
            if min_ver in _STRONG_VERSIONS:
                strong_binds.append(bind.raw)
            else:
                weak_found.append(f"bind {bind.raw}: ssl-min-ver {min_ver}")
        # Check for raw weak version tokens in options keys
        for key in opts_lower:
            if key in _WEAK_VERSIONS:
                weak_found.append(f"bind {bind.raw}: {key}")

    # --- Determine result ---
    if weak_found:
        return Finding(
            check_id="HAPR-TLS-001",
            status=Status.FAIL,
            message="Weak TLS protocol versions found in configuration.",
            evidence="; ".join(weak_found),
        )

    if strong_global:
        return Finding(
            check_id="HAPR-TLS-001",
            status=Status.PASS,
            message="Global ssl-default-bind-options enforces TLS 1.2+ via ssl-min-ver.",
            evidence=bind_opts_directives[0].args if bind_opts_directives else "",
        )

    if strong_binds:
        ssl_binds = [b for b in config.all_binds if b.ssl]
        if len(strong_binds) == len(ssl_binds):
            return Finding(
                check_id="HAPR-TLS-001",
                status=Status.PASS,
                message="All SSL bind lines enforce TLS 1.2+ via ssl-min-ver.",
                evidence="; ".join(strong_binds),
            )
        return Finding(
            check_id="HAPR-TLS-001",
            status=Status.PARTIAL,
            message=(
                f"Only {len(strong_binds)}/{len(ssl_binds)} SSL bind lines "
                "enforce TLS 1.2+."
            ),
            evidence="; ".join(strong_binds),
        )

    return Finding(
        check_id="HAPR-TLS-001",
        status=Status.FAIL,
        message="No minimum TLS version enforcement found (ssl-min-ver not set).",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-002  Weak ciphers
# ---------------------------------------------------------------------------

def check_no_weak_ciphers(config: HAProxyConfig) -> Finding:
    """Check that no weak cipher suites are configured.

    Inspects ``ssl-default-bind-ciphers`` in the global section and any
    cipher strings on individual bind lines for patterns known to be weak:
    DES, RC4, MD5, NULL, EXPORT, aNULL, eNULL, LOW.

    Returns PASS if no weak ciphers are found, FAIL if any are present.
    """
    g = config.global_section
    weak_hits: list[str] = []

    # Global default ciphers
    for d in g.get("ssl-default-bind-ciphers"):
        matches = _find_weak_ciphers(d.args)
        if matches:
            weak_hits.append(
                f"global ssl-default-bind-ciphers: {', '.join(matches)}"
            )

    # Per-bind ciphers
    for bind in config.all_binds:
        if not bind.ssl:
            continue
        cipher_str = bind.options.get("ciphers", "") or bind.options.get("ssl-default-bind-ciphers", "")
        if cipher_str:
            matches = _find_weak_ciphers(cipher_str)
            if matches:
                weak_hits.append(
                    f"bind {bind.raw}: {', '.join(matches)}"
                )

    if weak_hits:
        return Finding(
            check_id="HAPR-TLS-002",
            status=Status.FAIL,
            message="Weak cipher suites detected in TLS configuration.",
            evidence="; ".join(weak_hits),
        )

    return Finding(
        check_id="HAPR-TLS-002",
        status=Status.PASS,
        message="No weak cipher suites found in TLS configuration.",
        evidence="ssl-default-bind-ciphers and bind-level ciphers checked",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-003  ssl-default-bind-options present
# ---------------------------------------------------------------------------

def check_ssl_default_bind_options(config: HAProxyConfig) -> Finding:
    """Check that the global section contains ``ssl-default-bind-options``.

    This directive centralises TLS settings (min version, curves, etc.) so
    that every SSL frontend/listen inherits secure defaults.

    Returns PASS if present, FAIL if missing.
    """
    if config.global_section.has("ssl-default-bind-options"):
        value = config.global_section.get_value("ssl-default-bind-options") or ""
        return Finding(
            check_id="HAPR-TLS-003",
            status=Status.PASS,
            message="Global ssl-default-bind-options directive is present.",
            evidence=f"ssl-default-bind-options {value}",
        )

    return Finding(
        check_id="HAPR-TLS-003",
        status=Status.FAIL,
        message="Global ssl-default-bind-options directive is missing.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-004  ssl-default-bind-ciphers present
# ---------------------------------------------------------------------------

def check_ssl_default_bind_ciphers(config: HAProxyConfig) -> Finding:
    """Check that the global section contains ``ssl-default-bind-ciphers``.

    Without an explicit cipher list HAProxy falls back to the OpenSSL
    default, which may include weak or undesirable ciphers.

    Returns PASS if present, FAIL if missing.
    """
    if config.global_section.has("ssl-default-bind-ciphers"):
        value = config.global_section.get_value("ssl-default-bind-ciphers") or ""
        return Finding(
            check_id="HAPR-TLS-004",
            status=Status.PASS,
            message="Global ssl-default-bind-ciphers directive is present.",
            evidence=f"ssl-default-bind-ciphers {value}",
        )

    return Finding(
        check_id="HAPR-TLS-004",
        status=Status.FAIL,
        message="Global ssl-default-bind-ciphers directive is missing.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-005  ssl-default-bind-ciphersuites (TLS 1.3)
# ---------------------------------------------------------------------------

def check_ssl_default_bind_ciphersuites(config: HAProxyConfig) -> Finding:
    """Check that the global section contains ``ssl-default-bind-ciphersuites``.

    This directive controls which TLS 1.3 cipher suites are allowed.  If it
    is absent but ``ssl-default-bind-ciphers`` (TLS 1.2) is set, the result
    is PARTIAL.

    Returns PASS if present, PARTIAL if only TLS 1.2 ciphers are configured,
    FAIL if neither is present.
    """
    has_tls13 = config.global_section.has("ssl-default-bind-ciphersuites")
    has_tls12 = config.global_section.has("ssl-default-bind-ciphers")

    if has_tls13:
        value = config.global_section.get_value("ssl-default-bind-ciphersuites") or ""
        return Finding(
            check_id="HAPR-TLS-005",
            status=Status.PASS,
            message="Global ssl-default-bind-ciphersuites (TLS 1.3) directive is present.",
            evidence=f"ssl-default-bind-ciphersuites {value}",
        )

    if has_tls12:
        value = config.global_section.get_value("ssl-default-bind-ciphers") or ""
        return Finding(
            check_id="HAPR-TLS-005",
            status=Status.PARTIAL,
            message=(
                "TLS 1.2 ciphers are configured (ssl-default-bind-ciphers) but "
                "TLS 1.3 ciphersuites (ssl-default-bind-ciphersuites) are not."
            ),
            evidence=f"ssl-default-bind-ciphers {value}",
        )

    return Finding(
        check_id="HAPR-TLS-005",
        status=Status.FAIL,
        message=(
            "Neither ssl-default-bind-ciphersuites nor ssl-default-bind-ciphers "
            "is configured in the global section."
        ),
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-006  HSTS header
# ---------------------------------------------------------------------------

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# 1 year in seconds — considered the minimum for strong HSTS
_HSTS_STRONG_MAX_AGE = 31536000


def check_hsts_configured(config: HAProxyConfig) -> Finding:
    """Check that a Strict-Transport-Security (HSTS) header is configured.

    Looks for ``http-response set-header Strict-Transport-Security`` in any
    frontend, listen, or defaults section.

    Returns PASS if max-age >= 31536000 (1 year), PARTIAL if max-age is
    present but too short or zero, FAIL if the header is not set at all.
    """
    hsts_pattern = re.compile(
        r"^Strict-Transport-Security\b", re.IGNORECASE
    )

    # Check frontends, listens, defaults, and backends
    sections_to_check = (
        list(config.frontends)
        + list(config.listens)
        + list(config.defaults)
        + list(config.backends)
    )

    for section in sections_to_check:
        for d in section.get("http-response"):
            # Typical form: "set-header Strict-Transport-Security ..."
            # Also match "add-header Strict-Transport-Security ..."
            if d.args.startswith("set-header "):
                header_rest = d.args[len("set-header "):]
            elif d.args.startswith("add-header "):
                header_rest = d.args[len("add-header "):]
            else:
                continue
            if hsts_pattern.match(header_rest):
                section_name = getattr(section, "name", "defaults")
                # Extract and validate max-age value
                max_age_match = _HSTS_MAX_AGE_RE.search(header_rest)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age >= _HSTS_STRONG_MAX_AGE:
                        return Finding(
                            check_id="HAPR-TLS-006",
                            status=Status.PASS,
                            message=(
                                f"HSTS header is configured in section "
                                f"'{section_name}' with strong max-age "
                                f"({max_age} seconds)."
                            ),
                            evidence=f"http-response {d.args}",
                        )
                    if max_age == 0:
                        return Finding(
                            check_id="HAPR-TLS-006",
                            status=Status.PARTIAL,
                            message=(
                                f"HSTS header in section '{section_name}' has "
                                "max-age=0, which effectively disables HSTS."
                            ),
                            evidence=f"http-response {d.args}",
                        )
                    # 0 < max_age < _HSTS_STRONG_MAX_AGE
                    return Finding(
                        check_id="HAPR-TLS-006",
                        status=Status.PARTIAL,
                        message=(
                            f"HSTS header in section '{section_name}' has a "
                            f"weak max-age ({max_age} seconds). Recommended "
                            f"minimum is {_HSTS_STRONG_MAX_AGE} (1 year)."
                        ),
                        evidence=f"http-response {d.args}",
                    )
                # Header found but no max-age — treat as PARTIAL
                return Finding(
                    check_id="HAPR-TLS-006",
                    status=Status.PARTIAL,
                    message=(
                        f"HSTS header is configured in section "
                        f"'{section_name}' but no max-age value was found."
                    ),
                    evidence=f"http-response {d.args}",
                )

    return Finding(
        check_id="HAPR-TLS-006",
        status=Status.FAIL,
        message=(
            "No Strict-Transport-Security (HSTS) header found in any "
            "frontend, backend, listen, or defaults section."
        ),
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-007  DH parameter size
# ---------------------------------------------------------------------------

def check_dh_param_size(config: HAProxyConfig) -> Finding:
    """Check that ``tune.ssl.default-dh-param`` is set to >= 2048 in global.

    A small DH parameter size makes the server vulnerable to Logjam-style
    attacks.  The recommended minimum is 2048 bits.

    Returns PASS if >= 2048, PARTIAL if set but < 2048, FAIL if not set.
    """
    value = config.global_section.get_value("tune.ssl.default-dh-param")

    if value is None:
        return Finding(
            check_id="HAPR-TLS-007",
            status=Status.FAIL,
            message="tune.ssl.default-dh-param is not set in the global section.",
            evidence="not found",
        )

    try:
        size = int(value.strip())
    except (ValueError, TypeError):
        return Finding(
            check_id="HAPR-TLS-007",
            status=Status.FAIL,
            message=f"tune.ssl.default-dh-param has non-integer value: {value!r}.",
            evidence=f"tune.ssl.default-dh-param {value}",
        )

    if size >= 2048:
        return Finding(
            check_id="HAPR-TLS-007",
            status=Status.PASS,
            message=f"DH parameter size is {size} bits (>= 2048).",
            evidence=f"tune.ssl.default-dh-param {size}",
        )

    return Finding(
        check_id="HAPR-TLS-007",
        status=Status.PARTIAL,
        message=f"DH parameter size is {size} bits, which is below the recommended 2048.",
        evidence=f"tune.ssl.default-dh-param {size}",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-008  TLS session tickets disabled
# ---------------------------------------------------------------------------

def check_tls_session_tickets_disabled(config: HAProxyConfig) -> Finding:
    """Check that TLS session tickets are disabled via ``no-tls-tickets``.

    TLS session tickets can leak session keys if the server is compromised,
    weakening forward secrecy.  Disabling them via ``no-tls-tickets`` in
    ``ssl-default-bind-options`` (global) or on individual bind lines is
    recommended.

    Returns PASS if ``no-tls-tickets`` is set globally, PARTIAL if only on
    some bind lines, FAIL if not found anywhere.
    """
    g = config.global_section

    # --- Check global ssl-default-bind-options for no-tls-tickets ---
    global_found = False
    bind_opts_directives = g.get("ssl-default-bind-options")
    for d in bind_opts_directives:
        tokens = d.args.lower().split()
        if "no-tls-tickets" in tokens:
            global_found = True
            break

    if global_found:
        return Finding(
            check_id="HAPR-TLS-008",
            status=Status.PASS,
            message="TLS session tickets are disabled globally via ssl-default-bind-options.",
            evidence="ssl-default-bind-options contains no-tls-tickets",
        )

    # --- Check individual bind lines ---
    binds_with: list[str] = []
    ssl_binds: list[str] = []
    for bind in config.all_binds:
        if not bind.ssl:
            continue
        ssl_binds.append(bind.raw)
        opts_lower = {k.lower() for k in bind.options}
        if "no-tls-tickets" in opts_lower:
            binds_with.append(bind.raw)

    if binds_with:
        if len(binds_with) == len(ssl_binds):
            return Finding(
                check_id="HAPR-TLS-008",
                status=Status.PARTIAL,
                message=(
                    "TLS session tickets are disabled on all SSL bind lines, but "
                    "not in the global ssl-default-bind-options. Consider setting "
                    "it globally for consistency."
                ),
                evidence=f"no-tls-tickets on {len(binds_with)}/{len(ssl_binds)} SSL bind lines",
            )
        return Finding(
            check_id="HAPR-TLS-008",
            status=Status.PARTIAL,
            message=(
                f"TLS session tickets are disabled on only "
                f"{len(binds_with)}/{len(ssl_binds)} SSL bind lines."
            ),
            evidence=f"no-tls-tickets found on: {'; '.join(binds_with)}",
        )

    return Finding(
        check_id="HAPR-TLS-008",
        status=Status.FAIL,
        message=(
            "TLS session tickets are not disabled anywhere. Add 'no-tls-tickets' "
            "to ssl-default-bind-options in the global section."
        ),
        evidence="no-tls-tickets not found in global or any bind line",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-009  ssl-default-server-options present
# ---------------------------------------------------------------------------

def check_ssl_default_server_options(config: HAProxyConfig) -> Finding:
    """Check that ``ssl-default-server-options`` is set in the global section.

    This directive centralises TLS settings for backend (server-side)
    connections, similar to ``ssl-default-bind-options`` for frontend
    connections.  Without it, each server line must specify TLS options
    individually.

    Returns PASS if present, FAIL if missing.
    """
    if config.global_section.has("ssl-default-server-options"):
        value = config.global_section.get_value("ssl-default-server-options") or ""
        return Finding(
            check_id="HAPR-TLS-009",
            status=Status.PASS,
            message="Global ssl-default-server-options directive is present.",
            evidence=f"ssl-default-server-options {value}",
        )

    return Finding(
        check_id="HAPR-TLS-009",
        status=Status.FAIL,
        message=(
            "Global ssl-default-server-options directive is missing. "
            "Consider adding 'ssl-default-server-options ssl-min-ver TLSv1.2' "
            "to enforce TLS settings for backend connections."
        ),
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-010  OCSP stapling
# ---------------------------------------------------------------------------

def check_ocsp_stapling(config: HAProxyConfig) -> Finding:
    """Check that OCSP stapling is configured for SSL/TLS binds.

    Looks for OCSP-related configuration in:
      - Bind lines containing ``ocsp-update``, ``ocsp`` keywords, or
        references to ``.ocsp`` files.
      - Global section directives mentioning OCSP settings.

    Returns PASS if OCSP stapling is configured, FAIL if not configured,
    N/A if there are no SSL bind lines.
    """
    ssl_binds = [b for b in config.all_binds if b.ssl]
    if not ssl_binds:
        return Finding(
            check_id="HAPR-TLS-010",
            status=Status.NOT_APPLICABLE,
            message="No SSL bind lines found; OCSP stapling check not applicable.",
        )

    ocsp_evidence: list[str] = []

    # Check bind lines for OCSP references
    for bind in ssl_binds:
        raw_lower = bind.raw.lower()
        if "ocsp" in raw_lower:
            ocsp_evidence.append(f"bind {bind.raw}")
        else:
            # Check parsed options for ocsp-related keys
            for key in bind.options:
                if "ocsp" in key.lower():
                    ocsp_evidence.append(f"bind option {key} on {bind.raw}")
                    break

    # Check global section for OCSP directives
    for d in config.global_section.directives:
        if "ocsp" in d.keyword.lower() or "ocsp" in d.args.lower():
            ocsp_evidence.append(f"global: {d.keyword} {d.args}")

    if ocsp_evidence:
        return Finding(
            check_id="HAPR-TLS-010",
            status=Status.PASS,
            message="OCSP stapling is configured.",
            evidence="; ".join(ocsp_evidence),
        )

    return Finding(
        check_id="HAPR-TLS-010",
        status=Status.FAIL,
        message=(
            "OCSP stapling is not configured. Consider adding 'ocsp-update on' "
            "to SSL bind lines for improved certificate revocation checking."
        ),
        evidence="No OCSP configuration found in bind lines or global section",
    )


# ---------------------------------------------------------------------------
# HAPR-TLS-011  FIPS 140-2 approved ciphers only
# ---------------------------------------------------------------------------

# Keywords that indicate non-FIPS cipher components
_NON_FIPS_KEYWORDS = (
    "RC4", "DES", "3DES", "CAMELLIA", "SEED", "IDEA",
    "MD5", "CHACHA20", "NULL", "EXPORT", "ANULL", "ENULL",
)


def _find_non_fips_ciphers(cipher_string: str) -> list[str]:
    """Split a cipher string on ``:``, return ciphers containing non-FIPS keywords.

    Ciphers prefixed with ``!`` are exclusions and are skipped.
    """
    non_fips: list[str] = []
    for cipher in cipher_string.split(":"):
        c = cipher.strip()
        if not c or c.startswith("!"):
            continue
        c_upper = c.upper()
        for keyword in _NON_FIPS_KEYWORDS:
            if keyword in c_upper:
                non_fips.append(c)
                break
    return non_fips


def check_fips_ciphers(config: HAProxyConfig) -> Finding:
    """Check that only FIPS 140-2 approved cipher suites are configured.

    FIPS approved ciphers include AES (128/256), GCM, SHA256, SHA384,
    ECDHE, and DHE key exchange.  Non-FIPS ciphers include RC4, DES, 3DES,
    CHACHA20, CAMELLIA, SEED, IDEA, MD5, NULL, EXPORT, aNULL, eNULL.

    Inspects ``ssl-default-bind-ciphers`` and ``ssl-default-bind-ciphersuites``
    in the global section, plus cipher overrides on individual bind lines.

    Returns PASS if ciphers are set and all are FIPS-compliant, PARTIAL if
    ciphers are set but some non-FIPS ciphers are present, FAIL if no cipher
    configuration is found, N/A if there are no SSL bind lines.
    """
    ssl_binds = [b for b in config.all_binds if b.ssl]
    if not ssl_binds:
        return Finding(
            check_id="HAPR-TLS-011",
            status=Status.NOT_APPLICABLE,
            message="No SSL bind lines found; FIPS cipher check not applicable.",
        )

    g = config.global_section
    non_fips_hits: list[str] = []
    cipher_configured = False

    # Check global ssl-default-bind-ciphers
    for d in g.get("ssl-default-bind-ciphers"):
        cipher_configured = True
        matches = _find_non_fips_ciphers(d.args)
        if matches:
            non_fips_hits.append(
                f"global ssl-default-bind-ciphers: {', '.join(matches)}"
            )

    # Check global ssl-default-bind-ciphersuites (TLS 1.3)
    for d in g.get("ssl-default-bind-ciphersuites"):
        cipher_configured = True
        matches = _find_non_fips_ciphers(d.args)
        if matches:
            non_fips_hits.append(
                f"global ssl-default-bind-ciphersuites: {', '.join(matches)}"
            )

    # Check per-bind cipher overrides
    for bind in ssl_binds:
        cipher_str = bind.options.get("ciphers", "") or bind.options.get(
            "ssl-default-bind-ciphers", ""
        )
        ciphersuites_str = bind.options.get("ciphersuites", "")
        if cipher_str:
            cipher_configured = True
            matches = _find_non_fips_ciphers(cipher_str)
            if matches:
                non_fips_hits.append(
                    f"bind {bind.raw}: {', '.join(matches)}"
                )
        if ciphersuites_str:
            cipher_configured = True
            matches = _find_non_fips_ciphers(ciphersuites_str)
            if matches:
                non_fips_hits.append(
                    f"bind ciphersuites {bind.raw}: {', '.join(matches)}"
                )

    if not cipher_configured:
        return Finding(
            check_id="HAPR-TLS-011",
            status=Status.FAIL,
            message=(
                "No cipher configuration found. Without explicit cipher lists, "
                "non-FIPS ciphers may be negotiated."
            ),
            evidence="No ssl-default-bind-ciphers or bind-level ciphers configured",
        )

    if non_fips_hits:
        return Finding(
            check_id="HAPR-TLS-011",
            status=Status.PARTIAL,
            message="Non-FIPS cipher suites detected in TLS configuration.",
            evidence="; ".join(non_fips_hits),
        )

    return Finding(
        check_id="HAPR-TLS-011",
        status=Status.PASS,
        message="All configured cipher suites are FIPS 140-2 compliant.",
        evidence="ssl-default-bind-ciphers and bind-level ciphers checked",
    )


# ---------------------------------------------------------------------------
# HAPR-MTLS-001  Mutual TLS (client certificate verification)
# ---------------------------------------------------------------------------

def check_mtls_client_verification(config: HAProxyConfig) -> Finding:
    """Check for mutual TLS (client certificate verification) on SSL bind lines.

    Looks for ``verify required`` or ``verify optional`` along with ``ca-file``
    on SSL bind lines, or in the global ``ssl-default-bind-options``.

    Returns PASS if any bind has ``verify required`` with ``ca-file``,
    PARTIAL if ``verify optional`` is used, FAIL if no client verification
    is configured on SSL binds, N/A if there are no SSL bind lines.
    """
    ssl_binds = [b for b in config.all_binds if b.ssl]
    if not ssl_binds:
        return Finding(
            check_id="HAPR-MTLS-001",
            status=Status.NOT_APPLICABLE,
            message="No SSL bind lines found; mTLS check not applicable.",
        )

    verify_required: list[str] = []
    verify_optional: list[str] = []

    # Check global ssl-default-bind-options for verify directives
    global_verify = ""
    global_ca_file = False
    for d in config.global_section.get("ssl-default-bind-options"):
        raw_lower = d.args.lower()
        if "verify required" in raw_lower:
            global_verify = "required"
        elif "verify optional" in raw_lower:
            global_verify = "optional"
        if "ca-file" in raw_lower:
            global_ca_file = True

    if global_verify == "required" and global_ca_file:
        return Finding(
            check_id="HAPR-MTLS-001",
            status=Status.PASS,
            message="Mutual TLS is configured globally with verify required and ca-file.",
            evidence="ssl-default-bind-options contains verify required and ca-file",
        )

    # Check individual bind lines
    for bind in ssl_binds:
        raw_lower = bind.raw.lower()
        has_ca_file = "ca-file" in raw_lower or "ca-file" in {
            k.lower() for k in bind.options
        }
        if "verify required" in raw_lower:
            if has_ca_file:
                verify_required.append(bind.raw)
            else:
                # verify required without ca-file is incomplete
                verify_optional.append(bind.raw)
        elif "verify optional" in raw_lower:
            verify_optional.append(bind.raw)

    if verify_required:
        return Finding(
            check_id="HAPR-MTLS-001",
            status=Status.PASS,
            message=(
                f"Mutual TLS with verify required and ca-file is configured "
                f"on {len(verify_required)} SSL bind line(s)."
            ),
            evidence="; ".join(verify_required),
        )

    if verify_optional:
        return Finding(
            check_id="HAPR-MTLS-001",
            status=Status.PARTIAL,
            message=(
                f"Client certificate verification is set to optional on "
                f"{len(verify_optional)} SSL bind line(s). Consider using "
                f"'verify required' for stronger mTLS enforcement."
            ),
            evidence="; ".join(verify_optional),
        )

    if global_verify:
        status = Status.PASS if global_verify == "required" else Status.PARTIAL
        return Finding(
            check_id="HAPR-MTLS-001",
            status=status,
            message=f"Client certificate verification is set globally to verify {global_verify}.",
            evidence=f"ssl-default-bind-options verify {global_verify}",
        )

    return Finding(
        check_id="HAPR-MTLS-001",
        status=Status.FAIL,
        message=(
            "No client certificate verification (mTLS) is configured on any "
            "SSL bind line. Add 'verify required' and 'ca-file' to enforce mTLS."
        ),
        evidence="No verify required/optional found on SSL bind lines",
    )


# ---------------------------------------------------------------------------
# HAPR-MTLS-002  Client certificate CRL configured
# ---------------------------------------------------------------------------

def check_client_crl_configured(config: HAProxyConfig) -> Finding:
    """Check that a CRL (Certificate Revocation List) is configured for mTLS binds.

    When mutual TLS is used (``verify required`` or ``verify optional``), a
    ``crl-file`` should be configured to enable revocation checking of client
    certificates.

    Returns PASS if ``crl-file`` is configured on all mTLS bind lines,
    PARTIAL if only some have it, FAIL if mTLS is used without any CRL,
    N/A if no mTLS bind lines exist.
    """
    ssl_binds = [b for b in config.all_binds if b.ssl]

    mtls_binds: list[str] = []
    crl_binds: list[str] = []

    # Check global defaults
    global_mtls = False
    global_crl = False
    for d in config.global_section.get("ssl-default-bind-options"):
        raw_lower = d.args.lower()
        if "verify required" in raw_lower or "verify optional" in raw_lower:
            global_mtls = True
        if "crl-file" in raw_lower:
            global_crl = True

    if global_mtls and global_crl:
        return Finding(
            check_id="HAPR-MTLS-002",
            status=Status.PASS,
            message="CRL is configured globally alongside mTLS verification.",
            evidence="ssl-default-bind-options contains verify and crl-file",
        )

    # Check individual bind lines for mTLS and CRL
    for bind in ssl_binds:
        raw_lower = bind.raw.lower()
        has_verify = "verify required" in raw_lower or "verify optional" in raw_lower
        if has_verify:
            mtls_binds.append(bind.raw)
            has_crl = "crl-file" in raw_lower or "crl-file" in {
                k.lower() for k in bind.options
            }
            if has_crl:
                crl_binds.append(bind.raw)

    # If global mTLS but no global CRL, count all SSL binds as mTLS
    if global_mtls and not mtls_binds:
        mtls_binds = [b.raw for b in ssl_binds]
        for bind in ssl_binds:
            raw_lower = bind.raw.lower()
            if "crl-file" in raw_lower or "crl-file" in {
                k.lower() for k in bind.options
            }:
                crl_binds.append(bind.raw)

    if not mtls_binds:
        return Finding(
            check_id="HAPR-MTLS-002",
            status=Status.NOT_APPLICABLE,
            message="No mTLS bind lines found; CRL check not applicable.",
        )

    if len(crl_binds) == len(mtls_binds):
        return Finding(
            check_id="HAPR-MTLS-002",
            status=Status.PASS,
            message=f"CRL is configured on all {len(crl_binds)} mTLS bind line(s).",
            evidence="; ".join(crl_binds),
        )

    if crl_binds:
        return Finding(
            check_id="HAPR-MTLS-002",
            status=Status.PARTIAL,
            message=(
                f"CRL is configured on {len(crl_binds)}/{len(mtls_binds)} "
                f"mTLS bind line(s)."
            ),
            evidence=f"With CRL: {'; '.join(crl_binds)}; "
                      f"Without CRL: {'; '.join(b for b in mtls_binds if b not in crl_binds)}",
        )

    return Finding(
        check_id="HAPR-MTLS-002",
        status=Status.FAIL,
        message=(
            "mTLS is configured but no CRL file is specified. Add 'crl-file' "
            "to mTLS bind lines for client certificate revocation checking."
        ),
        evidence=f"mTLS binds without crl-file: {'; '.join(mtls_binds)}",
    )
