# HAPR — HAProxy Audit & Reporting Tool

Security baseline scoring, TLS scanning, CVE checking, and interactive reporting for HAProxy configurations.

No CIS benchmark or automated security audit tool exists for HAProxy — despite it being one of the most widely deployed reverse proxies/load balancers. HAPR fills that gap with a Python CLI that parses configs, probes live TLS endpoints, checks for known CVEs, scores against a custom security baseline (65 checks across 13 categories), generates interactive network topology graphs, and produces self-contained HTML reports.

## Features

- **Config-based audit** — Parse HAProxy configs and score against the HAPR Security Baseline (65 checks, 13 categories)
- **Live TLS scanning** — Probe endpoints via sslyze to verify actual TLS behavior (protocols, ciphers, certificates, vulnerabilities)
- **CVE checking** — Detect HAProxy version and query NVD for known vulnerabilities
- **Interactive topology** — Plotly-based network graph showing frontends → backends → servers
- **HTML reports** — Self-contained reports with executive summary, score breakdown, findings, and remediation guidance
- **Transparent scoring** — Every score traceable to individual checks with evidence

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Quick Start

```bash
# Config-only audit (terminal output)
hapr audit haproxy.cfg

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
hapr audit <config>                            Config-only audit → terminal
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
--nvd-api-key KEY      NVD API key (or NVD_API_KEY env var)
--socket PATH          HAProxy Unix socket for version detection
--haproxy-bin PATH     HAProxy binary path for version detection
--stats-url URL        HAProxy stats page URL for version detection
```

## HAPR Security Baseline

Modeled after CIS benchmark format. 13 categories, 65 checks.

| Category | ID Prefix | Source | Checks |
|----------|-----------|--------|--------|
| Process Security | HAPR-PROC | Config | chroot, non-root user, group, ulimits |
| TLS/SSL Config | HAPR-TLS | Config | min TLS version, cipher strength, HSTS, DH params |
| Access Control | HAPR-ACL | Config | ACLs, admin paths, rate limiting, stats auth |
| HTTP Security Headers | HAPR-HDR | Config | X-Frame-Options, CSP, XCTO, Referrer-Policy |
| Request Handling | HAPR-REQ | Config | body size, URL length, method filtering |
| Logging & Monitoring | HAPR-LOG | Config | log directives, format, stats security |
| Information Disclosure | HAPR-INF | Config | server header, error pages, version hiding |
| Timeout Config | HAPR-TMO | Config | client/server/connect/http-request timeouts |
| Backend Security | HAPR-BKD | Config | health checks, connection limits, backend SSL |
| Frontend Security | HAPR-FRT | Config | connection limits, HTTPS redirect, WAF, OWASP |
| Global & Defaults | HAPR-GBL | Config | defaults, socket perms, maxconn, DH params |
| Live TLS Scan | HAPR-SCAN | sslyze | protocol versions, ciphers, certs, vulns |
| Known Vulnerabilities | HAPR-CVE | NVD | critical/high CVEs, request smuggling |

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
    severity: critical
    weight: 10
    description: "All TLS bind lines should enforce TLS 1.2 or higher"
    rationale: "TLS 1.0 and 1.1 have known vulnerabilities"
    remediation: "Add 'ssl-min-ver TLSv1.2' to bind lines or global section"
    references:
      nist: ["SC-8", "SC-13"]
      owasp: ["A02:2021"]
    check_function: "tls.check_min_tls_version"
```

## Example Configs

Three example configs are included for testing:

- `examples/secure.cfg` — Well-hardened config (scores ~87%)
- `examples/insecure.cfg` — Deliberately weak config (scores ~12%)
- `examples/mixed.cfg` — Realistic production config with gaps (scores ~63%)

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## License

MIT
