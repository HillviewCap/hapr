# HAPR — HAProxy Audit & Reporting Tool

Security baseline scoring, TLS scanning, CVE checking, and interactive reporting for HAProxy configurations.

No CIS benchmark or automated security audit tool exists for HAProxy — despite it being one of the most widely deployed reverse proxies/load balancers. HAPR fills that gap with a Python CLI that parses configs, probes live TLS endpoints, checks for known CVEs, scores against a 103-check tiered security baseline across 13 categories, generates interactive network topology graphs, and produces self-contained HTML reports.

## Features

- **103-check security baseline** — Four-tier assessment model (Baseline → Level 1 → Level 2 → Level 3) mapped to DISA STIG, NIST SP 800-52, PCI DSS 4.0, OWASP, and SOC 2
- **Tiered assessments** — Run only the checks appropriate for your environment, from minimum viable security to zero-trust hardening
- **Live TLS scanning** — Probe endpoints via sslyze to verify actual TLS behavior (protocols, ciphers, certificates, vulnerabilities)
- **CVE checking** — Detect HAProxy version and query NVD for known vulnerabilities
- **Interactive topology** — Plotly-based network graph showing frontends → backends → servers
- **HTML reports** — Self-contained reports with executive summary, score breakdown, findings, and remediation guidance
- **Transparent scoring** — Every score traceable to individual checks with evidence

## Installation

```bash
# From PyPI (core — config audit, scoring, reports)
pip install hapr

# With live TLS scanning (sslyze)
pip install "hapr[scan]"

# With CVE checking (nvdlib)
pip install "hapr[cve]"

# Everything (TLS + CVE)
pip install "hapr[full]"

# From source (editable, with dev dependencies)
pip install -e ".[dev]"

# From source with pinned dependencies
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.10+.

## Quick Start

```bash
# Config-only audit (terminal output)
hapr audit haproxy.cfg

# Tiered assessments
hapr audit haproxy.cfg --tier baseline     # Minimum viable security (17 checks)
hapr audit haproxy.cfg --tier level1       # Standard production (58 checks)
hapr audit haproxy.cfg --tier level2       # Advanced threat protection (86 checks)
hapr audit haproxy.cfg                     # Full assessment, all tiers (103 checks)

# Generate HTML report
hapr audit haproxy.cfg -o report.html

# Full audit (config + TLS scan + CVE check)
hapr audit haproxy.cfg --full -o report.html

# Quick score
hapr score haproxy.cfg

# Topology graph
hapr graph haproxy.cfg -o topology.html

# List all baseline checks
hapr list-checks

# Standalone CVE check
hapr version-check 2.6.0

# Standalone TLS scan
hapr scan example.com:443
```

## CLI Reference

```
hapr audit <config>                            Config-only audit → terminal (all tiers)
hapr audit <config> --tier baseline            Baseline checks only
hapr audit <config> --tier level1              Baseline + Level 1 checks
hapr audit <config> --tier level2              Baseline + Level 1 + Level 2 checks
hapr audit <config> -o report.html             Config audit → HTML report
hapr audit <config> --scan                     Config + TLS scan (auto-discover)
hapr audit <config> --scan-targets host:port   Config + TLS scan (explicit)
hapr audit <config> --version-detect           Config + version/CVE check
hapr audit <config> --full -o report.html      Full audit → HTML report

hapr scan <host:port> ...                      Standalone TLS scan
hapr graph <config> -o topology.html           Topology graph only
hapr score <config>                            Quick score output
hapr list-checks                               List all baseline checks
hapr version-check <version>                   CVE check for a version
```

### Global Options

```
--baseline PATH        Custom baseline YAML file
--tier TIER            Assessment tier: baseline, level1, level2 (default: all)
--nvd-api-key KEY      NVD API key (or NVD_API_KEY env var)
--socket PATH          HAProxy Unix socket for version detection
--haproxy-bin PATH     HAProxy binary path for version detection
--stats-url URL        HAProxy stats page URL for version detection
--log-level LEVEL      Set logging verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: WARNING)
--log-file PATH        Write log output to a file
```

## HAPR Security Baseline

Modeled after CIS benchmark format. 13 categories, 103 checks across 4 tiers.

### Tier Model

| Tier | Purpose | Checks | Audience |
|------|---------|--------|----------|
| **Baseline** | Minimum viable security | 17 | Every deployment |
| **Level 1** | Standard production hardening | 41 | Production environments, SOC 2 |
| **Level 2** | Advanced threat protection | 28 | PCI DSS, NIST compliance |
| **Level 3** | Zero-trust / maximum hardening | 17 | Government, FIPS, zero-trust |

Tiers are cumulative: Level 1 runs Baseline + Level 1 checks (58 total), Level 2 runs all three (86 total), etc.

### Check Categories

| Category | ID Prefix | Checks | Coverage |
|----------|-----------|--------|----------|
| Process Security | HAPR-PROC | 5 | chroot, non-root user, group, ulimits, daemon mode |
| TLS/SSL Config | HAPR-TLS | 13 | min TLS version, ciphers, HSTS, DH params, session tickets, OCSP, FIPS, mTLS, CRL |
| Access Control | HAPR-ACL | 13 | ACLs, admin paths, rate limiting, stats auth, source IP, JWT, bot detection, IP reputation, API auth |
| HTTP Security Headers | HAPR-HDR | 9 | X-Frame-Options, CSP, XCTO, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP |
| Request Handling | HAPR-REQ | 7 | body size, URL length, method filtering, smuggling prevention, HTTP/2 limits, H2C smuggling |
| Logging & Monitoring | HAPR-LOG | 7 | log directives, format, level, httplog, dontlognull, remote syslog |
| Information Disclosure | HAPR-INF | 5 | server header, error pages, version hiding, XFF spoofing prevention |
| Timeout Config | HAPR-TMO | 6 | client/server/connect/http-request/keepalive timeouts, value validation |
| Backend Security | HAPR-BKD | 7 | health checks, connection limits, backend SSL, cookies, retry/redispatch, SSL verification, cache security |
| Frontend Security | HAPR-FRT | 12 | connection limits, HTTPS redirect, WAF, SQLi/XSS rules, XFF, bind restrictions, SPOE, compression BREACH, PROXY protocol |
| Global & Defaults | HAPR-GBL | 10 | defaults, socket perms, maxconn, DNS, hard-stop, nbproc, Lua limits, peer encryption |
| Live TLS Scan | HAPR-SCAN | 9 | protocol versions, ciphers, certs, vulns, renegotiation, key size, expiry, hostname match |
| Known Vulnerabilities | HAPR-CVE | 3 | critical/high CVEs, request smuggling |

### Compliance Mapping

Checks are mapped to industry standards in the baseline YAML:

- **DISA STIG** — Web Server SRG controls (CAT I/II/III)
- **NIST SP 800-52 Rev. 2** — TLS implementation guidelines
- **NIST SP 800-53** — Security control identifiers (SC, AC, IA, SI, AU, CM)
- **PCI DSS 4.0** — Payment card requirements (Req 2, 4, 6, 10)
- **OWASP** — Top 10 2021 mappings
- **SOC 2** — Trust Services Criteria (CC6, CC7)

### Scoring

- **Per check:** Pass=100%, Partial=50%, Fail=0%, N/A=excluded
- **Severity weights:** Critical=10, High=7, Medium=4, Low=2, Info=0
- **Category score:** weighted average of check results
- **Overall score:** weighted average of all scored checks
- **Letter grade:** A (90-100), B (80-89), C (70-79), D (60-69), F (<60)

Checks with `requires: scanner` or `requires: version` are excluded from scoring when those features aren't used.

## Custom Baselines

Override the built-in baseline with your own YAML:

```bash
hapr audit haproxy.cfg --baseline my-baseline.yaml
```

Check definitions follow this format:

```yaml
checks:
  - id: HAPR-TLS-001
    title: "Enforce minimum TLS 1.2"
    category: tls
    tier: baseline
    severity: critical
    weight: 10
    description: "All TLS bind lines should enforce TLS 1.2 or higher"
    rationale: "TLS 1.0 and 1.1 have known vulnerabilities"
    remediation: "Add 'ssl-min-ver TLSv1.2' to bind lines or global section"
    references:
      nist: ["SC-8", "SC-13"]
      owasp: ["A02:2021"]
      stig: ["SRG-APP-000439-WSR-000156"]
    check_function: "tls.check_min_tls_version"
```

The `tier` field controls which assessment level includes the check. Checks without a `tier` field always run.

## Example Configs

Three example configs are included for testing:

- `examples/secure.cfg` — Well-hardened config (Baseline: A 100%, Level 1: B 84%, Full: C 71%)
- `examples/insecure.cfg` — Deliberately weak config
- `examples/mixed.cfg` — Realistic production config with gaps

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (225 tests)
pytest tests/ -v
```

CI runs on GitHub Actions across Python 3.10, 3.11, and 3.12.

### Project Structure

```
hapr/
├── cli.py                          # Click CLI (audit, scan, graph, score, list-checks, version-check)
├── parser.py                       # HAProxy config parser (line-by-line state machine)
├── models.py                       # All dataclasses (config, audit, scan, CVE models)
├── scanner.py                      # sslyze-based live TLS scanning
├── report.py                       # Jinja2 HTML report renderer
├── visualizer.py                   # Plotly topology graph generator
├── data/
│   └── hapr-baseline.yaml          # Single source of truth (103 check definitions)
├── templates/
│   └── report.html.j2              # Jinja2 HTML report template
└── framework/
    ├── engine.py                   # Audit pipeline, scoring, tier filtering
    └── checks/                     # 13 check modules (pure functions)
        ├── process.py              # HAPR-PROC: chroot, user, group, ulimits, daemon
        ├── tls.py                  # HAPR-TLS + HAPR-MTLS: TLS config, OCSP, FIPS, mTLS
        ├── access.py               # HAPR-ACL + JWT/BOT/IPREP/API: access control
        ├── headers.py              # HAPR-HDR: security response headers
        ├── request.py              # HAPR-REQ + H2: request handling, HTTP/2
        ├── logging_checks.py       # HAPR-LOG: logging and monitoring
        ├── disclosure.py           # HAPR-INF: information disclosure
        ├── timeouts.py             # HAPR-TMO: timeout configuration
        ├── backend.py              # HAPR-BKD + CACHE: backend security
        ├── frontend.py             # HAPR-FRT + SPOE/COMP/PROXY: frontend security
        ├── global_defaults.py      # HAPR-GBL + LUA/PEER: global settings
        ├── tls_live.py             # HAPR-SCAN: live TLS scan checks
        └── cve.py                  # HAPR-CVE: known vulnerability checks
```

## License

MIT
