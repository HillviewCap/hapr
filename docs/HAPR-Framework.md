# HAPR Framework

The HAPR security framework defines what gets checked, how results are scored, and how the baseline can be extended. This page covers the scoring model, tier system, baseline structure, compliance mappings, and how to add or modify checks.

---

## Scoring Model

### Per-Check Scoring

Each check produces one of four statuses:

| Status | Score Value | Meaning |
|--------|-------------|---------|
| **Pass** | 100% | Requirement fully met |
| **Partial** | 50% | Requirement partially met |
| **Fail** | 0% | Requirement not met |
| **N/A** | Excluded | Check does not apply to this configuration |

### Severity Weights

Every check has a severity level that determines its weight in scoring. Higher-severity checks have more impact on the overall score:

| Severity | Weight | Examples |
|----------|--------|----------|
| **Critical** | 10 | Non-root user, minimum TLS 1.2, no critical CVEs |
| **High** | 7 | Chroot, HSTS, rate limiting, HTTPS redirect |
| **Medium** | 4 | Group directive, cipher suites, method filtering |
| **Low** | 2 | Ulimits, daemon mode, referrer policy |
| **Info** | 0 | Advisory checks (do not affect score) |

### Category Scoring

Checks are organized into 13 categories. Each category score is the weighted average of its checks:

```
category_score = sum(check_weight * status_value) / sum(check_weight)
```

N/A checks are excluded from both the numerator and denominator.

### Overall Score and Letter Grade

The overall score is the weighted average across all scored checks:

```
overall_score = sum(all_weights * status_values) / sum(all_weights)
```

| Grade | Score Range |
|-------|-------------|
| **A** | 90 -- 100% |
| **B** | 80 -- 89% |
| **C** | 70 -- 79% |
| **D** | 60 -- 69% |
| **F** | Below 60% |

### Special Handling

- Checks with `requires: scanner` are excluded from scoring when TLS scanning is not performed.
- Checks with `requires: version` are excluded when version detection is not performed.
- This prevents configs from being penalized for features that weren't tested.

---

## Tier System

The baseline uses a four-tier cumulative assessment model. Each tier builds on the previous one.

### Baseline -- Minimum Viable Security

**17 checks** | Every HAProxy deployment must pass these.

Covers the absolute essentials: running as non-root, chroot enabled, TLS 1.2 minimum, no weak ciphers, basic timeouts, logging, and critical CVE checks.

**Scope:** Static config analysis only. No external dependencies.

**Standards:** DISA STIG CAT I + essential CAT II, PCI DSS mandatory requirements.

### Level 1 -- Standard Production Security

**41 additional checks** (58 cumulative) | Standard production environments.

Adds security headers, access control validation, detailed logging, backend health checks, HTTPS redirect enforcement, cipher configuration, and connection limits.

**Scope:** Config analysis + header/policy validation + integration detection.

**Standards:** DISA STIG CAT II/III, PCI DSS Req 2/4/6/10, SOC 2 CC6/CC7, OWASP recommendations.

### Level 2 -- Advanced Threat Protection

**28 additional checks** (86 cumulative) | Sensitive data environments.

Adds live TLS scanning, WAF integration detection, advanced TLS features (OCSP, FIPS ciphers, mTLS), Lua safety controls, peer encryption, SPOE/SPOA validation, PROXY protocol restrictions, and cache security.

**Scope:** Config analysis + live TLS scanning + external integration validation.

**Standards:** PCI DSS 4.0 full compliance, NIST SP 800-52 Rev. 2, OWASP full header set.

### Level 3 -- Zero Trust / Maximum Hardening

**17 additional checks** (103 total) | Government, military, financial core, zero-trust.

Adds SQL injection and XSS protection rules, JWT validation, bot detection patterns, IP reputation integration, API gateway authentication, HTTP/2 hardening, and all live TLS vulnerability scanning.

**Scope:** Full stack including mTLS, HTTP smuggling defenses, and service mesh patterns.

**Standards:** Full DISA STIG, FIPS 140-2 cipher suites, architectural-level controls.

### Running Tiered Assessments

```bash
hapr audit haproxy.cfg --tier baseline     # 17 checks
hapr audit haproxy.cfg --tier level1       # 58 checks (baseline + level1)
hapr audit haproxy.cfg --tier level2       # 86 checks (baseline + level1 + level2)
hapr audit haproxy.cfg                     # 103 checks (all tiers)
```

---

## Check Categories

The 103 checks span 13 categories:

| Category | ID Prefix | Checks | Coverage |
|----------|-----------|--------|----------|
| Process Security | HAPR-PROC | 5 | chroot, non-root user, group, ulimits, daemon mode |
| TLS/SSL Config | HAPR-TLS | 13 | min TLS version, ciphers, HSTS, DH params, session tickets, OCSP, FIPS, mTLS, CRL |
| Access Control | HAPR-ACL | 13 | ACLs, admin paths, rate limiting, stats auth, source IP, JWT, bot detection, IP reputation, API auth |
| HTTP Security Headers | HAPR-HDR | 9 | X-Frame-Options, CSP, XCTO, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP |
| Request Handling | HAPR-REQ | 7 | body size, URL length, method filtering, smuggling prevention, HTTP/2 limits |
| Logging & Monitoring | HAPR-LOG | 7 | log directives, format, level, httplog, dontlognull, remote syslog |
| Information Disclosure | HAPR-INF | 5 | server header, error pages, version hiding, XFF spoofing prevention |
| Timeout Config | HAPR-TMO | 6 | client/server/connect/http-request/keepalive timeouts, value validation |
| Backend Security | HAPR-BKD | 7 | health checks, connection limits, backend SSL, cookies, retry/redispatch, cache security |
| Frontend Security | HAPR-FRT | 12 | connection limits, HTTPS redirect, WAF, SQLi/XSS rules, XFF, bind restrictions, compression |
| Global & Defaults | HAPR-GBL | 10 | defaults, socket perms, maxconn, DNS, hard-stop, Lua limits, peer encryption |
| Live TLS Scan | HAPR-SCAN | 9 | protocol versions, ciphers, certs, vulns, renegotiation, key size, expiry, hostname match |
| Known Vulnerabilities | HAPR-CVE | 3 | critical/high CVEs, request smuggling |

---

## Compliance Mappings

Each check in the baseline YAML is mapped to one or more industry standards:

| Framework | Description |
|-----------|-------------|
| **DISA STIG** | Web Server SRG controls (CAT I/II/III) |
| **NIST SP 800-52 Rev. 2** | TLS implementation guidelines |
| **NIST SP 800-53** | Security control identifiers (SC, AC, IA, SI, AU, CM) |
| **PCI DSS 4.0** | Payment card requirements (Req 2, 4, 6, 10) |
| **OWASP** | Top 10 2021 mappings |
| **SOC 2** | Trust Services Criteria (CC6, CC7) |

These mappings appear in the `references` field of each check definition and can be used to demonstrate compliance coverage for specific frameworks.

---

## Baseline YAML Structure

All checks are defined in a single file: `framework/hapr-baseline.yaml`. This is the single source of truth for the audit engine.

### File Layout

```yaml
metadata:
  name: HAPR Security Baseline
  version: "1.0.0"
  categories:
    - process
    - tls
    - access
    # ... all 13 categories
  severity_weights:
    critical: 10
    high: 7
    medium: 4
    low: 2
    info: 0
  tiers:
    baseline: "Minimum viable security - every deployment must pass"
    level1: "Standard production security"
    level2: "Enhanced security for sensitive environments"
    level3: "Maximum hardening for high-security environments"

checks:
  - id: HAPR-PROC-001
    title: Chroot Enabled
    category: process
    tier: baseline
    severity: high
    weight: 7
    description: >
      Verify that HAProxy is configured to chroot into a restricted directory.
    rationale: >
      Running HAProxy in a chroot jail confines the process to a dedicated
      directory tree, limiting filesystem access if compromised.
    remediation: >
      Add a chroot directive to the global section. Example: chroot /var/lib/haproxy
    references:
      nist:
        - SC-39
        - CM-7
      owasp:
        - "A05:2021 Security Misconfiguration"
      stig:
        - SRG-APP-000141-WSR-000076
    check_function: process.check_chroot
```

### Check Definition Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier following `HAPR-{CATEGORY}-{NNN}` pattern |
| `title` | Yes | Human-readable name |
| `category` | Yes | One of the 13 category names |
| `tier` | Yes | `baseline`, `level1`, `level2`, or `level3` |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, or `info` |
| `weight` | Yes | Numeric weight (must match severity: critical=10, high=7, etc.) |
| `description` | Yes | What the check verifies |
| `rationale` | Yes | Why this check matters for security |
| `remediation` | Yes | How to fix a failure |
| `references` | Yes | Compliance mappings (nist, owasp, stig) |
| `check_function` | Yes | Dotted path to the Python function (relative to `hapr.framework.checks`) |
| `requires` | No | `scanner` or `version` -- skip if dependency unavailable |

---

## Adding a New Check

To add a new security check to the framework:

### 1. Write the Check Function

Check functions are pure functions that take an `HAProxyConfig` and return a `Finding`. Create or edit a module in `hapr/framework/checks/`:

```python
# hapr/framework/checks/tls.py

from hapr.models import HAProxyConfig, Finding, Status

def check_my_new_feature(config: HAProxyConfig) -> Finding:
    """Verify that my new security feature is configured."""
    # Inspect the parsed config
    for frontend in config.frontends:
        for bind in frontend.binds:
            if "my-feature" in bind.options:
                return Finding(
                    check_id="HAPR-TLS-099",
                    status=Status.PASS,
                    message="My feature is properly configured.",
                    evidence=f"Found in frontend '{frontend.name}'"
                )

    return Finding(
        check_id="HAPR-TLS-099",
        status=Status.FAIL,
        message="My feature is not configured on any frontend.",
        evidence=""
    )
```

Key rules:
- Functions must be **pure**: `HAProxyConfig` in, `Finding` out. No side effects.
- The `check_id` in the Finding must match the `id` in the baseline YAML.
- Use `Status.PASS`, `Status.FAIL`, `Status.PARTIAL`, or `Status.NOT_APPLICABLE`.

### 2. Add the Check Definition to the Baseline

Add an entry to `framework/hapr-baseline.yaml`:

```yaml
  - id: HAPR-TLS-099
    title: My New Feature Configured
    category: tls
    tier: level1
    severity: medium
    weight: 4
    description: >
      Verify that my new security feature is enabled on all TLS frontends.
    rationale: >
      This feature improves security by doing X, which prevents Y.
    remediation: >
      Add 'my-feature' to all bind lines. Example: bind *:443 ssl crt cert.pem my-feature
    references:
      nist:
        - SC-8
      owasp:
        - "A02:2021 Cryptographic Failures"
      stig:
        - SRG-APP-000439-WSR-000156
    check_function: tls.check_my_new_feature
```

### 3. Register the Module (if new)

If you created a new check module file, import it in `hapr/framework/checks/__init__.py` so the engine can discover it.

### 4. Write Tests

Add tests in the `tests/` directory using inline HAProxy config strings:

```python
from hapr.parser import parse_string
from hapr.framework.checks.tls import check_my_new_feature
from hapr.models import Status

class TestMyNewFeature:
    def test_pass_when_configured(self):
        config = parse_string("""
            global
                log stdout format raw local0

            frontend web
                bind *:443 ssl crt cert.pem my-feature
                default_backend servers

            backend servers
                server s1 127.0.0.1:8080
        """)
        finding = check_my_new_feature(config)
        assert finding.status == Status.PASS

    def test_fail_when_missing(self):
        config = parse_string("""
            global
                log stdout format raw local0

            frontend web
                bind *:443 ssl crt cert.pem
                default_backend servers

            backend servers
                server s1 127.0.0.1:8080
        """)
        finding = check_my_new_feature(config)
        assert finding.status == Status.FAIL
```

### 5. Run Tests

```bash
pytest tests/ -v
```

---

## Modifying Existing Checks

### Changing Severity or Tier

Edit the check's `severity`, `weight`, or `tier` field in `framework/hapr-baseline.yaml`. No code changes needed.

### Changing Check Logic

Edit the corresponding function in `hapr/framework/checks/`. The function path is specified in the `check_function` field of the baseline YAML entry.

### Using a Custom Baseline

For organization-specific customizations without modifying the source, create your own YAML file and pass it with `--baseline`:

```bash
hapr audit haproxy.cfg --baseline my-org-baseline.yaml
```

Your custom baseline completely replaces the built-in one, so include all checks you want to run.

---

## Architecture Overview

```
framework/
  hapr-baseline.yaml          # All 103 check definitions (single source of truth)

hapr/
  framework/
    engine.py                 # Audit pipeline: loads baseline, resolves checks, scores
    baseline.py               # YAML loading and check retrieval
    checks/                   # 13 check modules (pure functions)
      __init__.py             # Module registry
      process.py              # HAPR-PROC checks
      tls.py                  # HAPR-TLS + HAPR-MTLS checks
      access.py               # HAPR-ACL + JWT/BOT/IPREP/API checks
      headers.py              # HAPR-HDR checks
      request.py              # HAPR-REQ + H2 checks
      logging_checks.py       # HAPR-LOG checks
      disclosure.py           # HAPR-INF checks
      timeouts.py             # HAPR-TMO checks
      backend.py              # HAPR-BKD + CACHE checks
      frontend.py             # HAPR-FRT + SPOE/COMP/PROXY checks
      global_defaults.py      # HAPR-GBL + LUA/PEER checks
      tls_live.py             # HAPR-SCAN checks (live TLS scanning)
      cve.py                  # HAPR-CVE checks (CVE detection)
```

The engine dynamically resolves check functions at runtime via `importlib.import_module()`. The `check_function` path in the YAML (e.g., `tls.check_min_tls_version`) maps to `hapr.framework.checks.tls.check_min_tls_version`.
