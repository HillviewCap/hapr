# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-12

### Added

- **103-check security baseline** across 13 categories with four-tier assessment model (Baseline, Level 1, Level 2, Level 3)
- **HAProxy config parser** — line-by-line state machine supporting global, defaults, frontend, backend, listen, resolvers, peers, and userlist sections
- **Audit engine** — dynamically loads check functions from baseline YAML, computes weighted scores per category and overall with letter grades (A–F)
- **CLI** (`hapr`) with commands: `audit`, `scan`, `graph`, `score`, `list-checks`, `version-check`
- **HTML report generation** — self-contained reports via Jinja2 with executive summary, score breakdown, findings, and remediation guidance
- **Plotly topology graphs** — interactive directed graphs showing frontends → backends → servers with severity-colored nodes
- **Live TLS scanning** via sslyze — probes endpoints for protocol versions, cipher suites, certificates, and known vulnerabilities
- **CVE checking** via NVD API — detects HAProxy version and queries for known CVEs
- **Version detection** — auto-detect HAProxy version via Unix socket, binary, or stats page
- **Tiered assessments** — `--tier baseline|level1|level2` to run only checks appropriate for your environment
- **Compliance mapping** — checks mapped to DISA STIG, NIST SP 800-52/800-53, PCI DSS 4.0, OWASP Top 10, and SOC 2
- **Custom baselines** — override built-in checks with `--baseline custom.yaml`
- **CI pipeline** — GitHub Actions across Python 3.10–3.12 with SAST (bandit) scanning
- **Example configs** — `secure.cfg`, `insecure.cfg`, `mixed.cfg` for testing and demonstration

### Infrastructure

- Package data (baseline YAML, report template) bundled inside the `hapr` package using `importlib.resources`
- Optional dependencies: `hapr[scan]` for sslyze, `hapr[cve]` for nvdlib, `hapr[full]` for both
- Release workflow for PyPI publishing via trusted OIDC on tag push

[0.1.0]: https://github.com/HillviewCap/hapr/releases/tag/v0.1.0
